
package main

import (
       "time"
       "context"
       "encoding/json"
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

             JSON, err := json.Marshal(result)
             fmt.Printf(string(JSON) + "\n")

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
