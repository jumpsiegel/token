
package main

import (
       "time"
       "context"
       "fmt"

       "github.com/algorand/go-algorand-sdk/client/v2/indexer"
)

const indexerAddress = "http://localhost:8980"
const indexerToken = ""

func main() {
     indexerClient, err := indexer.MakeClient(indexerAddress, indexerToken)
     _ = err

     // Parameters
     var notePrefix = "publishMessage"
     var next_round uint64 = 24

     for true {
         var nextToken = ""
         for true {
             result, err := indexerClient.SearchForTransactions().NotePrefix([]byte(notePrefix)).MinRound(next_round).NextToken(nextToken).Do(context.Background())
             _ = err

             for i := 0; i < len(result.Transactions); i++ {
                var t = result.Transactions[i].ApplicationTransaction
                if string(t.ApplicationArgs[0]) == "publishMessage" {
                    fmt.Printf(string(t.ApplicationArgs[1]) + "\n")
                }
             }   

             if result.NextToken != "" {
                 nextToken = result.NextToken
             } else {
                 next_round = result.CurrentRound + 1
                 break
             }
         }
         time.Sleep(1 * time.Second)
     }
}
