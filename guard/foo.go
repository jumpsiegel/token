// https://github.com/algorand-devrel/demo-avm1.1

// go get -d github.com/algorand/go-algorand-sdk/...
// go get -u github.com/algorand/indexer/fetcher
//
// # github.com/algorand/go-algorand/crypto
// ../../go/pkg/mod/github.com/algorand/go-algorand@v0.0.0-20220216190355-cbf1939eeb26/crypto/batchverifier.go:33:11: fatal error: sodium.h: No such file or directory
//   33 | // #include "sodium.h"


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
