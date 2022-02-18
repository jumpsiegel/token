
package main

import (
       "time"
       "context"
       "fmt"
       "encoding/json"
       "github.com/algorand/go-algorand-sdk/client/v2/indexer"
       "github.com/algorand/go-algorand-sdk/client/v2/common/models"
)

const indexerAddress = "http://localhost:8980"
const indexerToken = ""

func lookAtTxn(t models.Transaction) {
  var at = t.ApplicationTransaction
  if len(at.ApplicationArgs) == 0 {
    return
  }

  JSON, err := json.Marshal(t)
  _ = err
  fmt.Printf(string(JSON))

  fmt.Printf("%d\n", at.ApplicationId)
  if string(at.ApplicationArgs[0]) == "publishMessage" { // The note filter is effectively the same thing
      var vaa = at.ApplicationArgs[1]
      fmt.Printf(t.Sender + " -> " + string(vaa) + "\n")
  }
}

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
                var t = result.Transactions[i]
                if len(t.InnerTxns) > 0 {
                    for q := 0; q < len(t.InnerTxns); q++ {
                      lookAtTxn(t.InnerTxns[q])
                    }
                } else {
                  lookAtTxn(t)
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
