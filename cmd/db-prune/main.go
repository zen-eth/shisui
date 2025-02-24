package main

import (
	"fmt"
	"os"
	"sync"

	pebbledb "github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
	"github.com/zen-eth/shisui/history"
	"github.com/zen-eth/shisui/internal/debug"
	"github.com/zen-eth/shisui/internal/flags"
	"github.com/zen-eth/shisui/storage/pebble"
)

var app = flags.NewApp("prune headerWithProof data")

var BaseDirFlag = &cli.StringFlag{
	Name:     "base-dir",
	Usage:    "base directory for all the shisui2 database",
	Value:    "",
}

var NumberFlag = &cli.IntFlag{
	Name:     "number",
	Usage:    "the number of the db to prune",
	Value: 0,
}

func init() {
	app.Action = prune
	app.Flags = []cli.Flag{BaseDirFlag, NumberFlag}
	flags.AutoEnvVars(app.Flags, "SHISUI")

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		_, err = fmt.Fprintln(os.Stderr, err)
		if err != nil {
			log.Error("Failed to write error to stderr", "err", err)
		}
		os.Exit(1)
	}
}

func prune(ctx *cli.Context) error {
	var sync sync.WaitGroup;
	baseDir := ctx.String(BaseDirFlag.Name)
	if baseDir == "" {
		return fmt.Errorf("base dir is required")
	}
	number := ctx.Int(NumberFlag.Name)
	if number == 0 {
		return fmt.Errorf("number is required")
	}
	sync.Add(number)
	for i :=0; i < number; i++ {
		dbPath := fmt.Sprintf("%s/shisui2_node%d", baseDir, i+1)
		go func ()  {
			pruneDB(dbPath)
			defer sync.Done()	
		}()
	}
	sync.Wait()
	return nil
}

func pruneDB(dbPath string) error {
	db, err := pebble.NewDB(dbPath, 16, 400, "history")
	if err != nil {
		return  err
	}
	iter, err := db.NewIter(nil)
	if err != nil {
		return  err
	}
	batch := db.NewBatch()
	noneCount := 0
	preMergeCount := 0
	for iter.Last(); iter.Valid(); iter.Prev() {
		data := iter.Value()
		headerWithProof := new(history.HeaderWithProof)
		err = headerWithProof.UnmarshalSSZ(data)
		if err != nil {
			continue
		}
		switch headerWithProof.Proof[0] {
		case 0:
			if len(headerWithProof.Proof) != 1 {
				continue
			}
			batch.Delete(iter.Key(), nil)
			noneCount++
		case 1:
			if (len(headerWithProof.Proof) == 32 * 15) {
				continue
			}
			headerWithProof.Proof = headerWithProof.Proof[1:]
			newData, err := headerWithProof.MarshalSSZ();
			if err != nil {
				return err
			}
			batch.Set(iter.Key(), newData, nil)
			preMergeCount++
		}
	}
	batch.Commit(&pebbledb.WriteOptions{Sync: true})
	fmt.Println()
	fmt.Printf("db %s, noneCount %d, preMergeCount %d\n", dbPath, noneCount, preMergeCount)
	return nil
}