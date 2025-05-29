// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package portalwire

import (
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// lookup performs a network search for nodes close to the given target. It approaches the
// target by querying nodes that are closer to it on each iteration. The given target does
// not need to be an actual node identifier.
type lookup struct {
	tab         *Table
	queryfunc   queryFunc
	replyCh     chan []*enode.Node
	cancelCh    <-chan struct{}
	asked, seen map[enode.ID]bool
	result      nodesByDistance
	replyBuffer []*enode.Node
	queries     int
}

type queryFunc func(*enode.Node) ([]*enode.Node, error)

func newLookup(ctx context.Context, tab *Table, target enode.ID, q queryFunc) *lookup {
	it := &lookup{
		tab:       tab,
		queryfunc: q,
		asked:     make(map[enode.ID]bool),
		seen:      make(map[enode.ID]bool),
		result:    nodesByDistance{target: target},
		replyCh:   make(chan []*enode.Node, alpha),
		cancelCh:  ctx.Done(),
		queries:   -1,
	}
	// Don't query further if we hit ourself.
	// Unlikely to happen often in practice.
	it.asked[tab.self().ID()] = true
	return it
}

// run runs the lookup to completion and returns the closest nodes found.
func (it *lookup) run() []*enode.Node {
	for it.advance() {
	}
	return it.result.entries
}

// advance advances the lookup until any new nodes have been found.
// It returns false when the lookup has ended.
func (it *lookup) advance() bool {
	for it.startQueries() {
		select {
		case nodes := <-it.replyCh:
			it.replyBuffer = it.replyBuffer[:0]
			for _, n := range nodes {
				if n != nil && !it.seen[n.ID()] {
					it.seen[n.ID()] = true
					it.result.push(n, bucketSize)
					it.replyBuffer = append(it.replyBuffer, n)
				}
			}
			it.queries--
			if len(it.replyBuffer) > 0 {
				return true
			}
		case <-it.cancelCh:
			it.shutdown()
		}
	}
	return false
}

func (it *lookup) shutdown() {
	for it.queries > 0 {
		<-it.replyCh
		it.queries--
	}
	it.queryfunc = nil
	it.replyBuffer = nil
}

func (it *lookup) startQueries() bool {
	if it.queryfunc == nil {
		return false
	}

	// The first query returns nodes from the local table.
	if it.queries == -1 {
		closest := it.tab.findnodeByID(it.result.target, bucketSize, false)
		// Avoid finishing the lookup too quickly if table is empty. It'd be better to wait
		// for the table to fill in this case, but there is no good mechanism for that
		// yet.
		if len(closest.entries) == 0 {
			it.slowdown()
		}
		it.queries = 1
		it.replyCh <- closest.entries
		return true
	}

	// Ask the closest nodes that we haven't asked yet.
	for i := 0; i < len(it.result.entries) && it.queries < alpha; i++ {
		n := it.result.entries[i]
		if !it.asked[n.ID()] {
			it.asked[n.ID()] = true
			it.queries++
			go it.query(n, it.replyCh)
		}
	}
	// The lookup ends when no more nodes can be asked.
	return it.queries > 0
}

func (it *lookup) slowdown() {
	sleep := time.NewTimer(1 * time.Second)
	defer sleep.Stop()
	select {
	case <-sleep.C:
	case <-it.tab.closeReq:
	}
}

func (it *lookup) query(n *enode.Node, reply chan<- []*enode.Node) {
	r, err := it.queryfunc(n)
	if !errors.Is(err, errClosed) { // avoid recording failures on shutdown.
		success := len(r) > 0
		it.tab.trackRequest(n, success, r)
		if err != nil {
			it.tab.log.Trace("FINDNODE failed", "id", n.ID(), "err", err)
		}
	}
	reply <- r
}

// lookupIterator performs lookup operations and iterates over all seen nodes.
// When a lookup finishes, a new one is created through nextLookup.
type lookupIterator struct {
	buffer     []*enode.Node
	nextLookup lookupFunc
	ctx        context.Context
	cancel     func()
	lookup     *lookup
}

type lookupFunc func(ctx context.Context) *lookup

func newLookupIterator(ctx context.Context, next lookupFunc) *lookupIterator {
	ctx, cancel := context.WithCancel(ctx)
	return &lookupIterator{ctx: ctx, cancel: cancel, nextLookup: next}
}

// Node returns the current node.
func (it *lookupIterator) Node() *enode.Node {
	if len(it.buffer) == 0 {
		return nil
	}
	return it.buffer[0]
}

// Next moves to the next node.
func (it *lookupIterator) Next() bool {
	// Consume next node in buffer.
	if len(it.buffer) > 0 {
		it.buffer = it.buffer[1:]
	}
	// Advance the lookup to refill the buffer.
	for len(it.buffer) == 0 {
		if it.ctx.Err() != nil {
			it.lookup = nil
			it.buffer = nil
			return false
		}
		if it.lookup == nil {
			it.lookup = it.nextLookup(it.ctx)
			continue
		}
		if !it.lookup.advance() {
			it.lookup = nil
			continue
		}
		it.buffer = it.lookup.replyBuffer
	}
	return true
}

// Close ends the iterator.
func (it *lookupIterator) Close() {
	it.cancel()
}

// nodeQueue 按距离排序的节点队列
type nodeQueue struct {
	target enode.ID
	nodes  []*enode.Node
}

func newNodeQueue(target enode.ID) *nodeQueue {
	return &nodeQueue{target: target, nodes: make([]*enode.Node, 0)}
}

func (nq *nodeQueue) push(n *enode.Node) {
	// 按距离插入排序
	dist := enode.LogDist(nq.target, n.ID())
	insertPos := 0
	for i, existing := range nq.nodes {
		if enode.LogDist(nq.target, existing.ID()) > dist {
			insertPos = i
			break
		}
		insertPos = i + 1
	}

	// 插入节点
	nq.nodes = append(nq.nodes, nil)
	copy(nq.nodes[insertPos+1:], nq.nodes[insertPos:])
	nq.nodes[insertPos] = n

	// 限制队列大小
	if len(nq.nodes) > bucketSize {
		nq.nodes = nq.nodes[:bucketSize]
	}
}

func (nq *nodeQueue) pop() *enode.Node {
	if len(nq.nodes) == 0 {
		return nil
	}
	node := nq.nodes[0]
	nq.nodes = nq.nodes[1:]
	return node
}

func (nq *nodeQueue) len() int {
	return len(nq.nodes)
}

// ContentLookupResult contains found result
type ContentLookupResult struct {
	Content     []byte
	UtpTransfer bool
	FoundAt     *enode.Node
}

// contentLookupState hold lookup state
type contentLookupState struct {
	target     enode.ID
	contentKey []byte
	protocol   *PortalProtocol
	ctx        context.Context
	cancel     context.CancelFunc

	contacted  map[enode.ID]bool
	pending    map[enode.ID]bool
	candidates *nodeQueue

	// concurrency control
	resultChan    chan *ContentLookupResult
	newNodeChan   chan *enode.Node // new node found notify
	queryDoneChan chan *enode.Node // query done notify
	mu            sync.Mutex
	found         atomic.Bool
	activeQueries int // active query count

	trace *Trace
}

func newContentLookupState(ctx context.Context, cancel context.CancelFunc, p *PortalProtocol, contentId []byte, contentKey []byte, trace *Trace) *contentLookupState {
	return &contentLookupState{
		target:        enode.ID(contentId),
		contentKey:    contentKey,
		protocol:      p,
		ctx:           ctx,
		cancel:        cancel,
		contacted:     make(map[enode.ID]bool),
		pending:       make(map[enode.ID]bool),
		candidates:    newNodeQueue(enode.ID(contentId)),
		resultChan:    make(chan *ContentLookupResult, 1),
		newNodeChan:   make(chan *enode.Node, 100),
		queryDoneChan: make(chan *enode.Node, 100),
		trace:         trace,
	}
}

// run completely event drive for content look up
func (state *contentLookupState) run() {
	defer func() {
		state.cancel()
	}()
	state.initCandidates()
	const maxConcurrent = 3
	activeChan := make(chan struct{}, maxConcurrent)

	// 启动初始查询
	state.startAvailableQueries(activeChan)

	// 主事件循环
	for {
		select {
		case <-state.ctx.Done():
			return

		case newNode := <-state.newNodeChan:
			state.addNewCandidate(newNode)
			// try start new queries
			state.startAvailableQueries(activeChan)

		case completedNode := <-state.queryDoneChan:
			state.onQueryCompleted(completedNode)
			<-activeChan
			// try start new queries
			state.startAvailableQueries(activeChan)
			if state.isLookupComplete() {
				// It will not affect the normal process
				// If no content is found, it read a nil value
				// state.resultChan will not be closed anytime
				select {
				case state.resultChan <- nil:
				default:
				}
				return
			}
		}
	}
}

// startAvailableQueries 启动可用的查询
func (state *contentLookupState) startAvailableQueries(activeChan chan struct{}) {
	for {
		if state.found.Load() {
			return
		}

		state.mu.Lock()
		// 检查是否还能启动新查询
		if len(activeChan) >= cap(activeChan) {
			state.mu.Unlock()
			return
		}

		// 获取下一个候选节点
		node := state.candidates.pop()
		if node == nil {
			state.mu.Unlock()
			return
		}

		// 检查是否已经联系过
		if state.contacted[node.ID()] || state.pending[node.ID()] {
			state.mu.Unlock()
			continue
		}

		state.pending[node.ID()] = true
		state.activeQueries++
		state.mu.Unlock()

		// 启动查询
		go func(n *enode.Node) {
			select {
			case activeChan <- struct{}{}:
				state.queryNode(n)
			case <-state.ctx.Done():
				// 清理状态
				state.mu.Lock()
				delete(state.pending, n.ID())
				state.contacted[n.ID()] = true
				state.activeQueries--
				state.mu.Unlock()
				// 通知查询完成
				select {
				case state.queryDoneChan <- n:
				case <-state.ctx.Done():
				}
				return
			}
		}(node)
	}
}

// queryNode 查询单个节点
func (state *contentLookupState) queryNode(node *enode.Node) {
	// 通知查询完成
	defer func() {
		select {
		case state.queryDoneChan <- node:
		case <-state.ctx.Done():
		}
	}()

	if state.found.Load() {
		return
	}

	flag, content, err := state.protocol.findContent(node, state.contentKey)
	if err != nil {
		state.protocol.Log.Debug("content lookup query failed",
			"node", node.ID(), "err", err)
		return
	}

	hexId := "0x" + node.ID().String()
	if state.trace != nil {
		state.mu.Lock()

		dis := state.protocol.Distance(node.ID(), state.target)

		state.trace.Metadata[hexId] = &NodeMetadata{
			Enr:      node.String(),
			Distance: hexutil.Encode(dis[:]),
		}
		state.mu.Unlock()
	}

	switch flag {
	case ContentRawSelector, ContentConnIdSelector:
		contentBytes, ok := content.([]byte)
		if !ok {
			state.protocol.Log.Error("invalid content type",
				"node", node.ID(), "content", content)
			return
		}

		result := &ContentLookupResult{
			Content:     contentBytes,
			UtpTransfer: flag == ContentConnIdSelector,
			FoundAt:     node,
		}

		if !state.found.Load() && state.found.CompareAndSwap(false, true) {
			select {
			case state.resultChan <- result:
			default:
			}
		}

	case ContentEnrsSelector:
		nodes, ok := content.([]*enode.Node)
		if !ok {
			state.protocol.Log.Error("invalid enrs type",
				"node", node.ID(), "content", content)
			return
		}
		if state.trace != nil {
			state.handleEnrsWithTrace(hexId, nodes)
			return
		}
		for _, newNode := range nodes {
			if newNode.ID() == state.protocol.Self().ID() {
				continue
			}
			select {
			case state.newNodeChan <- newNode:
			case <-state.ctx.Done():
				return
			}
		}
	}
}

func (state *contentLookupState) handleEnrsWithTrace(fromHexId string, nodes []*enode.Node) {
	respByNode := RespByNode{
		RespondedWith: make([]string, 0, len(nodes)),
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	for _, newNode := range nodes {
		idInner := "0x" + newNode.ID().String()
		respByNode.RespondedWith = append(respByNode.RespondedWith, idInner)

		if _, ok := state.trace.Metadata[idInner]; !ok {
			dis := state.protocol.Distance(newNode.ID(), state.target)
			state.trace.Metadata[idInner] = &NodeMetadata{
				Enr:      newNode.String(),
				Distance: hexutil.Encode(dis[:]),
			}
		}
		if newNode.ID() == state.protocol.Self().ID() {
			continue
		}
		select {
		case state.newNodeChan <- newNode:
		case <-state.ctx.Done():
			return
		}
	}
	state.trace.Responses[fromHexId] = respByNode
}

// addNewCandidate 添加新候选节点
func (state *contentLookupState) addNewCandidate(node *enode.Node) {
	if state.found.Load() {
		return
	}
	// 检查是否已经处理过
	if !state.contacted[node.ID()] && !state.pending[node.ID()] {
		state.candidates.push(node)
	}
}

// onQueryCompleted 处理查询完成
func (state *contentLookupState) onQueryCompleted(node *enode.Node) {
	state.mu.Lock()
	defer state.mu.Unlock()

	delete(state.pending, node.ID())
	state.contacted[node.ID()] = true
	state.activeQueries--
}

// isLookupComplete 检查查找是否完成
func (state *contentLookupState) isLookupComplete() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	fmt.Println("found=", state.found.Load(), ";candidates.len=", state.candidates.len(), ";activeQueries=", state.activeQueries)
	return state.found.Load() || (state.candidates.len() == 0 && state.activeQueries == 0)
}

// hasLocalResult 检查本地是否有结果
func (state *contentLookupState) hasLocalResult() bool {
	if content, err := state.protocol.storage.Get(state.contentKey, state.target[:]); err == nil {
		result := &ContentLookupResult{
			Content:     content,
			UtpTransfer: false,
			FoundAt:     state.protocol.Self(),
		}
		state.resultChan <- result
		return true
	}
	return false
}

// initCandidates 初始化候选节点
func (state *contentLookupState) initCandidates() {
	closestNodes := state.protocol.findNodesCloseToContent(state.target[:], bucketSize)
	for _, node := range closestNodes {
		if node.ID() != state.protocol.Self().ID() {
			state.candidates.push(node)
		}
	}
}
