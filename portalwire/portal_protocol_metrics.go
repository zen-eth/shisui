package portalwire

import (
	"database/sql"
	"errors"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"strings"
)

var ErrMetricsDisabled = errors.New("metrics are disabled")

type portalMetrics struct {
	messagesReceivedAccept      *metrics.Meter
	messagesReceivedNodes       *metrics.Meter
	messagesReceivedFindNodes   *metrics.Meter
	messagesReceivedFindContent *metrics.Meter
	messagesReceivedContent     *metrics.Meter
	messagesReceivedOffer       *metrics.Meter
	messagesReceivedPing        *metrics.Meter
	messagesReceivedPong        *metrics.Meter

	messagesSentAccept      *metrics.Meter
	messagesSentNodes       *metrics.Meter
	messagesSentFindNodes   *metrics.Meter
	messagesSentFindContent *metrics.Meter
	messagesSentContent     *metrics.Meter
	messagesSentOffer       *metrics.Meter
	messagesSentPing        *metrics.Meter
	messagesSentPong        *metrics.Meter

	utpInFailConn     *metrics.Counter
	utpInFailRead     *metrics.Counter
	utpInFailDeadline *metrics.Counter
	utpInSuccess      *metrics.Counter

	utpOutFailConn     *metrics.Counter
	utpOutFailWrite    *metrics.Counter
	utpOutFailDeadline *metrics.Counter
	utpOutSuccess      *metrics.Counter

	contentDecodedTrue  *metrics.Counter
	contentDecodedFalse *metrics.Counter
	contentDiscard      *metrics.Counter

	gossipDropCount *metrics.Counter
}

func newPortalMetrics(protocolName string) *portalMetrics {
	return &portalMetrics{
		messagesReceivedAccept:      metrics.NewRegisteredMeter("portal/"+protocolName+"/received/accept", nil),
		messagesReceivedNodes:       metrics.NewRegisteredMeter("portal/"+protocolName+"/received/nodes", nil),
		messagesReceivedFindNodes:   metrics.NewRegisteredMeter("portal/"+protocolName+"/received/find_nodes", nil),
		messagesReceivedFindContent: metrics.NewRegisteredMeter("portal/"+protocolName+"/received/find_content", nil),
		messagesReceivedContent:     metrics.NewRegisteredMeter("portal/"+protocolName+"/received/content", nil),
		messagesReceivedOffer:       metrics.NewRegisteredMeter("portal/"+protocolName+"/received/offer", nil),
		messagesReceivedPing:        metrics.NewRegisteredMeter("portal/"+protocolName+"/received/ping", nil),
		messagesReceivedPong:        metrics.NewRegisteredMeter("portal/"+protocolName+"/received/pong", nil),
		messagesSentAccept:          metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/accept", nil),
		messagesSentNodes:           metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/nodes", nil),
		messagesSentFindNodes:       metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/find_nodes", nil),
		messagesSentFindContent:     metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/find_content", nil),
		messagesSentContent:         metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/content", nil),
		messagesSentOffer:           metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/offer", nil),
		messagesSentPing:            metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/ping", nil),
		messagesSentPong:            metrics.NewRegisteredMeter("portal/"+protocolName+"/sent/pong", nil),
		utpInFailConn:               metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/inbound/fail_conn", nil),
		utpInFailRead:               metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/inbound/fail_read", nil),
		utpInFailDeadline:           metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/inbound/fail_deadline", nil),
		utpInSuccess:                metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/inbound/success", nil),
		utpOutFailConn:              metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/outbound/fail_conn", nil),
		utpOutFailWrite:             metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/outbound/fail_write", nil),
		utpOutFailDeadline:          metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/outbound/fail_deadline", nil),
		utpOutSuccess:               metrics.NewRegisteredCounter("portal/"+protocolName+"/utp/outbound/success", nil),
		contentDecodedTrue:          metrics.NewRegisteredCounter("portal/"+protocolName+"/content/decoded/true", nil),
		contentDecodedFalse:         metrics.NewRegisteredCounter("portal/"+protocolName+"/content/decoded/false", nil),
		contentDiscard:              metrics.NewRegisteredCounter("portal/"+protocolName+"/content/gossip/discard", nil),
		gossipDropCount:             metrics.NewRegisteredCounter("portal/"+protocolName+"/gossip/drop", nil),
	}
}

type PortalStorageMetrics struct {
	RadiusRatio         *metrics.GaugeFloat64
	EntriesCount        *metrics.Gauge
	ContentStorageUsage *metrics.Gauge
}

const (
	countEntrySql          = "SELECT COUNT(1) FROM kvstore;"
	contentStorageUsageSql = "SELECT SUM( length(value) ) FROM kvstore;"
)

func NewPortalStorageMetrics(network string, db *sql.DB) (*PortalStorageMetrics, error) {
	if !metrics.Enabled() {
		return nil, ErrMetricsDisabled
	}

	if network != History.Name() && network != Beacon.Name() && network != State.Name() {
		log.Debug("Unknow network for metrics", "network", network)
		return nil, errors.New("unknow network for metrics")
	}

	var countSql string
	var contentSql string
	if network == Beacon.Name() {
		countSql = strings.Replace(countEntrySql, "kvstore", "beacon", 1)
		contentSql = strings.Replace(contentStorageUsageSql, "kvstore", "beacon", 1)
		contentSql = strings.Replace(contentSql, "value", "content_value", 1)
	} else {
		countSql = countEntrySql
		contentSql = contentStorageUsageSql
	}

	storageMetrics := &PortalStorageMetrics{}

	storageMetrics.RadiusRatio = metrics.NewRegisteredGaugeFloat64("portal/"+network+"/radius_ratio", nil)
	storageMetrics.RadiusRatio.Update(1)

	storageMetrics.EntriesCount = metrics.NewRegisteredGauge("portal/"+network+"/entry_count", nil)
	log.Debug("Counting entities in " + network + " storage for metrics")
	var res = new(int64)
	q := db.QueryRow(countSql)
	if errors.Is(q.Err(), sql.ErrNoRows) {
		storageMetrics.EntriesCount.Update(0)
	} else if q.Err() != nil {
		log.Error("Querry execution error", "network", network, "metric", "entry_count", "err", q.Err())
		return nil, q.Err()
	} else {
		err := q.Scan(res)
		if err != nil {
			return nil, err
		}
		storageMetrics.EntriesCount.Update(*res)
	}

	storageMetrics.ContentStorageUsage = metrics.NewRegisteredGauge("portal/"+network+"/content_storage", nil)
	log.Debug("Counting storage usage (bytes) in " + network + " for metrics")
	var res2 = new(int64)
	q2 := db.QueryRow(contentSql)
	if errors.Is(q2.Err(), sql.ErrNoRows) {
		storageMetrics.ContentStorageUsage.Update(0)
	} else if q2.Err() != nil {
		log.Error("Querry execution error", "network", network, "metric", "entry_count", "err", q2.Err())
		return nil, q2.Err()
	} else {
		err := q2.Scan(res2)
		if err != nil {
			return nil, err
		}
		storageMetrics.ContentStorageUsage.Update(*res2)
	}

	return storageMetrics, nil
}
