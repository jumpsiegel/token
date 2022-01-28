
from algosdk.logic import get_application_address
from algosdk.future import transaction

import sys
import math
import base64
import pprint

sys.path.append("..")

from setup import Setup

class TEST2(Setup):
    def __init__(self) -> None:
        super().__init__()

    def test(self, args):
        self.publish(base64.b32decode("AEAAAAAAAEAJ7ASQOAUPXGMS3ISFVZNNET5A4PVP7OJ4MRKD52ADFQ7OYNCYOFDRXU3IJ37OLYKLWBZYEO5SCTXHWATSHDPGHTLTNR7DA4524RYA5UAGDRFSB4AAADVEAAA4NGQ3DJS52M3L6HPWU55PWUA7YJO3P7AJHDFQQWK2T32HGJS4WTYAAAAAAAAAAAFCAAQWLAEXHESAUCWAHOMEID7ITBKURY5KNA6NBVGZ35NVMWLGT6VDAEAACCKTJ5GFIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJW63DBNZQSAVDFON2CAVDPNNSW4AAAAAAAAAAAAAAAAAAAAAAAA==="))

    def publish(self, data):
        d = self.read_global_state(self.client, self.target.getAddress(), self.args.appid)
        pprint.pprint(d)
        #print(data)

        #   async publish (data: PythData): Promise<PublishInfo> {
        #     const publishInfo: PublishInfo = { status: StatusCode.OK }
        # 
        #     const txParams = await this.algodClient.getTransactionParams().do()
        #     txParams.fee = 1000
        #     txParams.flatFee = true
        # 
        
        
        self.guardianCount = d["gscount"]
        self.stepSize = d["vssize"]
        self.numOfVerifySteps = math.ceil(self.guardianCount / self.stepSize)

        if (self.guardianCount == 0) or (self.stepSize == 0):
                raise Exception('cannot get guardian count and/or step-size from global state')

        #
        # (!)
        # Stateless programs cannot access state nor stack from stateful programs, so
        # for the VAA Verify program to use the guardian set, we pass the global state as TX argument,
        # (and check it against the current global list to be sure it's ok). This way it can be read by
        # VAA verifier as a stateless program CAN DO READS of call transaction arguments in a group.
        # The same technique is used for the note field, where the payload is set.
        #

        #     try 
        guardianKeys = ""
        for i in range(self.guardianCount):
            k = i.to_bytes(8, byteorder='big')
            gk = d[k.decode()]
            guardianKeys = guardianKeys + gk

        pprint.pprint(guardianKeys)
            
        gid = []
        sigSubsets = []
        for i in range(self.numOfVerifySteps):
            st = self.stepSize * i
            sigSetLen = 132 * self.stepSize

            # const keySubset = guardianKeys.slice(st, i < this.numOfVerifySteps - 1 ? st + this.stepSize : undefined)
            keySubset = guardianKeys[st:]
            if i < this.numOfVerifySteps - 1:
                keySubset = keySubset[:self.stepSize]
        #         sigSubsets.push(data.signatures.slice(i * sigSetLen, i < this.numOfVerifySteps - 1 ? ((i * sigSetLen) + sigSetLen) : undefined))
        #         this.pclib.addVerifyTx(gid, this.compiledVerifyProgram.hash, txParams, data.vaaBody, keySubset, this.guardianCount)
        #       }
        #       this.pclib.addPriceStoreTx(gid, this.vaaProcessorOwner, txParams, data.symbol, data.vaaBody.slice(51))
        #       const txId = await this.pclib.commitVerifyTxGroup(gid, this.compiledVerifyProgram.bytes, sigSubsets, this.vaaProcessorOwner, this.signCallback.bind(this))
        #       publishInfo.txid = txId
        #     } catch (e: any) {
        #       publishInfo.status = StatusCode.ERROR_SUBMIT_MESSAGE
        #       publishInfo.reason = e.response.text ? e.response.text : e.toString()
        #       return publishInfo
        #     }
        # 
        #     return publishInfo
        #   }
        
        
        #    this.commitVerifyTxGroup = async function (programBytes, sigSubsets) {
        #      algosdk.assignGroupID(this.groupTx)
        #      const signedGroup = []
        #      let i = 0
        #      for (const tx of this.groupTx) {
        #        const lsig = new algosdk.LogicSigAccount(programBytes, [Buffer.from(sigSubsets[i++], 'hex')])
        #        const stxn = algosdk.signLogicSigTransaction(tx, lsig)
        #        signedGroup.push(stxn.blob)
        #      }
        #
        #      // Save transaction for debugging.
        #
        #      // fs.unlinkSync('signedgroup.stxn')
        #
        #      // for (let i = 0; i < signedGroup.length; ++i) {
        #      //   fs.appendFileSync('signedgroup.stxn', signedGroup[i])
        #      // }
        #
        #      // const dr = await algosdk.createDryrun({
        #      //   client: algodClient,
        #      //   txns: drtxns,
        #      //   sources: [new algosdk.modelsv2.DryrunSource('lsig', fs.readFileSync(vaaVerifyStatelessProgramFilename).toString('utf8'))]
        #      // })
        #      // // const drobj = await algodClient.dryrun(dr).do()
        #      // fs.writeFileSync('dump.dr', algosdk.encodeObj(dr.get_obj_for_encoding(true)))
        #
        #      // Submit the transaction
        #      const tx = await this.algodClient.sendRawTransaction(signedGroup).do()
        #      this.groupTx = []
        #      return tx.txId
        #    }
        #
        #    this.addVerifyTx = function (sender, params, payload, gksubset, totalguardians) {
        #      const appArgs = []
        #      appArgs.push(new Uint8Array(Buffer.from('verify')),
        #        new Uint8Array(Buffer.from(gksubset.join(''), 'hex')),
        #        algosdk.encodeUint64(parseInt(totalguardians)))
        #
        #      const tx = algosdk.makeApplicationNoOpTxn(sender,
        #        params,
        #        this.appId,
        #        appArgs, undefined, undefined, undefined,
        #        new Uint8Array(payload))
        #      this.groupTx.push(tx)
        #
        #      return tx.txID()
        #    }
        #  }

if __name__ == "__main__":
    test2 = TEST2()
    test2.main()

