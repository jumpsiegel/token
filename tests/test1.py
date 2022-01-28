from time import time, sleep
from typing import List, Tuple, Dict, Any, Optional, Union
from base64 import b64decode
import base64
import random
import hashlib

from algosdk.v2client.algod import AlgodClient
from algosdk.kmd import KMDClient
from algosdk import account, mnemonic
from algosdk.encoding import decode_address
from algosdk.future import transaction
from pyteal import compileTeal, Mode, Expr
from pyteal import *
from algosdk.logic import get_application_address
from Cryptodome.Hash import SHA512

import pprint

class Account:
    """Represents a private key and address for an Algorand account"""

    def __init__(self, privateKey: str) -> None:
        self.sk = privateKey
        self.addr = account.address_from_private_key(privateKey)
        # print (privateKey + " -> " + self.getMnemonic())

    def getAddress(self) -> str:
        return self.addr

    def getPrivateKey(self) -> str:
        return self.sk

    def getMnemonic(self) -> str:
        return mnemonic.from_private_key(self.sk)

    @classmethod
    def FromMnemonic(cls, m: str) -> "Account":
        return cls(mnemonic.to_private_key(m))

class PendingTxnResponse:
    def __init__(self, response: Dict[str, Any]) -> None:
        self.poolError: str = response["pool-error"]
        self.txn: Dict[str, Any] = response["txn"]

        self.applicationIndex: Optional[int] = response.get("application-index")
        self.assetIndex: Optional[int] = response.get("asset-index")
        self.closeRewards: Optional[int] = response.get("close-rewards")
        self.closingAmount: Optional[int] = response.get("closing-amount")
        self.confirmedRound: Optional[int] = response.get("confirmed-round")
        self.globalStateDelta: Optional[Any] = response.get("global-state-delta")
        self.localStateDelta: Optional[Any] = response.get("local-state-delta")
        self.receiverRewards: Optional[int] = response.get("receiver-rewards")
        self.senderRewards: Optional[int] = response.get("sender-rewards")

        self.innerTxns: List[Any] = response.get("inner-txns", [])
        self.logs: List[bytes] = [b64decode(l) for l in response.get("logs", [])]

class TEST1:
    def __init__(self) -> None:
        self.ALGOD_ADDRESS = "http://localhost:4001"
        self.ALGOD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.FUNDING_AMOUNT = 100_000_000

        self.KMD_ADDRESS = "http://localhost:4002"
        self.KMD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.KMD_WALLET_NAME = "unencrypted-default-wallet"
        self.KMD_WALLET_PASSWORD = ""

        self.kmdAccounts : Optional[List[Account]] = None

        self.accountList : List[Account] = []

    def waitForTransaction(
            self, client: AlgodClient, txID: str, timeout: int = 10
    ) -> PendingTxnResponse:
        lastStatus = client.status()
        lastRound = lastStatus["last-round"]
        startRound = lastRound
    
        while lastRound < startRound + timeout:
            pending_txn = client.pending_transaction_info(txID)
    
            if pending_txn.get("confirmed-round", 0) > 0:
                return PendingTxnResponse(pending_txn)
    
            if pending_txn["pool-error"]:
                raise Exception("Pool error: {}".format(pending_txn["pool-error"]))
    
            lastStatus = client.status_after_block(lastRound + 1)
    
            lastRound += 1
    
        raise Exception(
            "Transaction {} not confirmed after {} rounds".format(txID, timeout)
        )

    def getKmdClient(self) -> KMDClient:
        return KMDClient(self.KMD_TOKEN, self.KMD_ADDRESS)
    
    def getGenesisAccounts(self) -> List[Account]:
        if self.kmdAccounts is None:
            kmd = self.getKmdClient()
    
            wallets = kmd.list_wallets()
            walletID = None
            for wallet in wallets:
                if wallet["name"] == self.KMD_WALLET_NAME:
                    walletID = wallet["id"]
                    break
    
            if walletID is None:
                raise Exception("Wallet not found: {}".format(self.KMD_WALLET_NAME))
    
            walletHandle = kmd.init_wallet_handle(walletID, self.KMD_WALLET_PASSWORD)
    
            try:
                addresses = kmd.list_keys(walletHandle)
                privateKeys = [
                    kmd.export_key(walletHandle, self.KMD_WALLET_PASSWORD, addr)
                    for addr in addresses
                ]
                self.kmdAccounts = [Account(sk) for sk in privateKeys]
            finally:
                kmd.release_wallet_handle(walletHandle)
    
        return self.kmdAccounts
    
    def getTemporaryAccount(self, client: AlgodClient) -> Account:
        if len(self.accountList) == 0:
            sks = [account.generate_account()[0] for i in range(2)]
            self.accountList = [Account(sk) for sk in sks]
    
            genesisAccounts = self.getGenesisAccounts()
            suggestedParams = client.suggested_params()
    
            txns: List[transaction.Transaction] = []
            for i, a in enumerate(self.accountList):
                fundingAccount = genesisAccounts[i % len(genesisAccounts)]
                txns.append(
                    transaction.PaymentTxn(
                        sender=fundingAccount.getAddress(),
                        receiver=a.getAddress(),
                        amt=self.FUNDING_AMOUNT,
                        sp=suggestedParams,
                    )
                )
    
            txns = transaction.assign_group_id(txns)
            signedTxns = [
                txn.sign(genesisAccounts[i % len(genesisAccounts)].getPrivateKey())
                for i, txn in enumerate(txns)
            ]
    
            client.send_transactions(signedTxns)
    
            self.waitForTransaction(client, signedTxns[0].get_txid())
    
        return self.accountList.pop()
    
    def getAlgodClient(self) -> AlgodClient:
        return AlgodClient(self.ALGOD_TOKEN, self.ALGOD_ADDRESS)

    def hashy(self, method: str) -> Bytes:
        chksum = SHA512.new(truncate="256")
        chksum.update(method)
        return chksum.digest()

    def fullyCompileContract(self, client: AlgodClient, contract: Expr) -> bytes:
        teal = compileTeal(contract, mode=Mode.Application, version=5)
        response = client.compile(teal)
        r = b64decode(response["result"])
        assert self.hashy( bytes("Program", 'utf-8') + r) == decode_address(response["hash"])
        return [r, decode_address(response["hash"])]

    def read_state(self, client, addr, app_id):
        results = client.account_info(addr)
        apps_created = results['created-apps']
        for app in apps_created:
            if app['id'] == app_id:
                return app;
        return {}
        
    def getContracts1(self, client: AlgodClient) -> Tuple[bytes, bytes]:
        validUpdateHash = Bytes("validUpdateHash")

        def approval_program(): 
            on_create = Seq(
                App.globalPut(validUpdateHash, Bytes("")),
                Return(Int(1))
            )

            # In a real world case, this would also 
            #   1) set the clear 
            #   2) check some byzatine voting rules from the governance body to see if we should be allowed to 
            #      update this hash
            #   3) Remember the fact that we have executed this governance action so that we cannot replay it later

            on_sethash = Seq(
                App.globalPut(validUpdateHash, Txn.application_args[1]), 
                Approve()
            )
            on_test = Seq(
                Log(Bytes("test1")),
                Approve()
            )

            on_call_method = Txn.application_args[0]
            on_call = Cond(
                [on_call_method == Bytes("sethash"), on_sethash],
                [on_call_method == Bytes("test"), on_test],
            )

            on_approve = Seq(
                Approve(),
            )

            on_update = Seq(
                Assert(Sha512_256(Concat(Bytes("Program"), Txn.approval_program())) == App.globalGet(validUpdateHash)),
                Return(Int(1))
            )

            program = Cond(
                [Txn.application_id() == Int(0), on_create],
                [Txn.on_completion() == OnComplete.NoOp, on_call],
                [Txn.on_completion() == OnComplete.DeleteApplication, on_approve],
                [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
                [
                    Or(
                        Txn.on_completion() == OnComplete.OptIn,
                        Txn.on_completion() == OnComplete.CloseOut,
                    ),
                    Reject(),
                ],
            )
            return program
    
        def clear_state_program():
            return Approve()
    
        APPROVAL_PROGRAM = self.fullyCompileContract(client, approval_program())
        CLEAR_STATE_PROGRAM = self.fullyCompileContract(client, clear_state_program())

        return APPROVAL_PROGRAM, CLEAR_STATE_PROGRAM

    def getContracts2(self, client: AlgodClient) -> Tuple[bytes, bytes]:
        validUpdateHash = Bytes("validUpdateHash")

        def approval_program(): 
            on_create = Seq(
                App.globalPut(validUpdateHash, Bytes("")),
                Return(Int(1))
            )

            on_sethash = Seq(
                App.globalPut(validUpdateHash, Txn.application_args[1]), 
                Approve()
            )
            on_test = Seq(
                Log(Bytes("test2")),
                Approve()
            )

            on_call_method = Txn.application_args[0]
            on_call = Cond(
                [on_call_method == Bytes("sethash"), on_sethash],
                [on_call_method == Bytes("test"), on_test],
            )

            on_approve = Seq(
                Approve(),
            )

            on_update = Seq(
                Assert(Sha512_256(Concat(Bytes("Program"), Txn.approval_program())) == App.globalGet(validUpdateHash)),
                Approve(),
            )

            program = Cond(
                [Txn.application_id() == Int(0), on_create],
                [Txn.on_completion() == OnComplete.NoOp, on_call],
                [Txn.on_completion() == OnComplete.DeleteApplication, on_approve],
                [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
                [
                    Or(
                        Txn.on_completion() == OnComplete.OptIn,
                        Txn.on_completion() == OnComplete.CloseOut,
                    ),
                    Reject(),
                ],
            )
            return program
    
        def clear_state_program():
            return Approve()
    
        APPROVAL_PROGRAM = self.fullyCompileContract(client, approval_program())
        CLEAR_STATE_PROGRAM = self.fullyCompileContract(client, clear_state_program())

        return APPROVAL_PROGRAM, CLEAR_STATE_PROGRAM

    def createTEST1App(
        self,
        client: AlgodClient,
        sender: Account,
    ) -> int:
        approval, clear = self.getContracts1(client)
    
        globalSchema = transaction.StateSchema(num_uints=2, num_byte_slices=6)
        localSchema = transaction.StateSchema(num_uints=0, num_byte_slices=0)
    
        app_args = [ ]
    
        txn = transaction.ApplicationCreateTxn(
            sender=sender.getAddress(),
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval[0],
            clear_program=clear[0],
            global_schema=globalSchema,
            local_schema=localSchema,
            app_args=app_args,
            sp=client.suggested_params(),
        )
    
        signedTxn = txn.sign(sender.getPrivateKey())
    
        client.send_transaction(signedTxn)
    
        response = self.waitForTransaction(client, signedTxn.get_txid())
        assert response.applicationIndex is not None and response.applicationIndex > 0
        return response.applicationIndex

    def updateTEST1App(
        self,
        client: AlgodClient,
        sender: Account,
        appid: int
    ) -> int:
        approval, clear = self.getContracts2(client)

        # Lets see which program we are talking too
        txn = transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"test"],
            sp=client.suggested_params(),
        )
        signedTxn = txn.sign(sender.getPrivateKey())
        client.send_transaction(signedTxn)
        response = self.waitForTransaction(client, signedTxn.get_txid())
        pprint.pprint(response.logs)

        # This should fail...
        txn = transaction.ApplicationUpdateTxn(
            index=appid,
            sender=sender.getAddress(),
            approval_program=approval[0],
            clear_program=clear[0],
            app_args=[ ],
            sp=client.suggested_params(),
        )
    
        signedTxn = txn.sign(sender.getPrivateKey())
        try:
            client.send_transaction(signedTxn)
            self.waitForTransaction(client, signedTxn.get_txid())
            print("We did not fail as expected?!")
        except Exception:
            print("We failed as expected")

        txn1 = transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"sethash", approval[1]],
            sp=client.suggested_params(),
        )

        txn2 = transaction.ApplicationUpdateTxn(
            index=appid,
            sender=sender.getAddress(),
            approval_program=approval[0],
            clear_program=clear[0],
            app_args=[ ],
            sp=client.suggested_params(),
        )

        transaction.assign_group_id([txn1, txn2])
    
        signedTxn1 = txn1.sign(sender.getPrivateKey())
        signedTxn2 = txn2.sign(sender.getPrivateKey())

        client.send_transactions([signedTxn1, signedTxn2])
        response = self.waitForTransaction(client, signedTxn2.get_txid())
        pprint.pprint(response.__dict__)

        # Lets see which program we are talking too
        txn = transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"test"],
            sp=client.suggested_params(),
        )
        signedTxn = txn.sign(sender.getPrivateKey())
        client.send_transaction(signedTxn)
        response = self.waitForTransaction(client, signedTxn.get_txid())
        pprint.pprint(response.logs)

    def simple_test1(self):
        client = self.getAlgodClient()
        player1 = self.getTemporaryAccount(client)

        appID = self.createTEST1App(client=client, sender=player1)
        print("appID = " + str(appID))

        print("application state")
        pprint.pprint(self.read_state(client, player1.getAddress(), appID))

        self.updateTEST1App(client=client, sender=player1, appid=appID)

if __name__ == "__main__":
    test1 = TEST1()
    test1.simple_test1()
