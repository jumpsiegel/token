package main

import (
        "context"
        "strings"

        "github.com/algorand/go-algorand/rpcs"
        "github.com/algorand/indexer/fetcher"
        "github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {

        f, err := fetcher.ForNetAndToken("http://localhost:4001", strings.Repeat("a", 64), log)
        if err != nil {
                log.Fatalf("Failed to create fetcher: %+v", err)
        }
        f.SetBlockHandler(handler)

        f.Run(context.Background())
}

func handler(ctx context.Context, cert *rpcs.EncodedBlockCert) error {

        for _, stxn := range cert.Block.Payset {
                log.Printf("%+v", stxn.SignedTxn.Txn.Type)
        }

        return nil
}
