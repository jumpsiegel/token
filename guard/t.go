
package main

import (
       "time"
       "context"
       "fmt"
//       "encoding/json"
       "github.com/algorand/go-algorand-sdk/client/v2/indexer"
)

const indexerAddress = "http://localhost:8980"
const indexerToken = ""

func main() {
     indexerClient, err := indexer.MakeClient(indexerAddress, indexerToken)
     _ = err

     // Parameters
     var notePrefix = "publishMessage"
     var next_round uint64 = 0

     for true {
         var nextToken = ""
         for true {
             result, err := indexerClient.SearchForTransactions().NotePrefix([]byte(notePrefix)).MinRound(next_round).NextToken(nextToken).Do(context.Background())
             _ = err

             for i := 0; i < len(result.Transactions); i++ {
//                JSON, err := json.MarshalIndent(result.Transactions[i], ",", " ")
//                _ = err
//                fmt.Printf(string(JSON))

                var t = result.Transactions[i].ApplicationTransaction
                if string(t.ApplicationArgs[0]) == "publishMessage" { // The note filter is effectively the same thing
                    var vaa = t.ApplicationArgs[1]
                    fmt.Printf(result.Transactions[i].Sender + " -> " + string(vaa) + "\n")
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
