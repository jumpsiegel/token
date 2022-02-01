# source .. few messages...
#   <smartContract>  <EmitterChain>   ->   <algo asset>  <smartContract> <EmitterChain>
#   <GovernanceIndex (int)> -> <algo app>      19 publicKeys for VAA signers  <32*19>

# Lots of sequence numbers... optimize for space
#   <EmitterSource> <SequenceNumber>  ->   <Bit>  (duplicate suppresion)

from time import time, sleep
from typing import List, Tuple, Dict, Any, Optional, Union
from base64 import b64decode
import base64
import random
import hashlib
import uuid
import sys
import json
import uvarint

from local_blob import LocalBlob

from algosdk.v2client.algod import AlgodClient
from algosdk.kmd import KMDClient
from algosdk import account, mnemonic
from algosdk.encoding import decode_address
from algosdk.future import transaction
from pyteal import compileTeal, Mode, Expr
from pyteal import *
from algosdk.logic import get_application_address

from algosdk.future.transaction import LogicSigAccount

import pprint

max_keys = 16
max_bytes_per_key = 127
bits_per_byte = 8

bits_per_key = max_bytes_per_key * bits_per_byte
max_bytes = max_bytes_per_key * max_keys
max_bits = bits_per_byte * max_bytes

class TmplSig:
    """KeySig class reads in a json map containing assembly details of a template smart signature and allows you to populate it with the variables
    In this case we are only interested in a single variable, the key which is a byte string to make the address unique.
    In this demo we're using random strings but in practice you can choose something meaningful to your application
    """

    def __init__(self, name):
        # Read the source map
        with open("{}.json".format(name)) as f:
            self.map = json.loads(f.read())

        self.src = base64.b64decode(self.map["bytecode"])
        self.sorted = dict(
            sorted(
                self.map["template_labels"].items(),
                key=lambda item: item[1]["position"],
            )
        )

    def populate(self, values: Dict[str, Union[str, int]]) -> LogicSigAccount:
        """populate uses the map to fill in the variable of the bytecode and returns a logic sig with the populated bytecode"""
        # Get the template source
        contract = list(base64.b64decode(self.map["bytecode"]))

        shift = 0
        for k, v in self.sorted.items():
            if k in values:
                pos = v["position"] + shift
                if v["bytes"]:
                    val = bytes.fromhex(values[k])
                    lbyte = uvarint.encode(len(val))
                    # -1 to account for the existing 00 byte for length
                    shift += (len(lbyte) - 1) + len(val)
                    # +1 to overwrite the existing 00 byte for length
                    contract[pos : pos + 1] = lbyte + val
                else:
                    val = uvarint.encode(values[k])
                    # -1 to account for existing 00 byte
                    shift += len(val) - 1
                    # +1 to overwrite existing 00 byte
                    contract[pos : pos + 1] = val

        # Create a new LogicSigAccount given the populated bytecode
        return LogicSigAccount(bytes(contract))

    def get_bytecode_chunk(self, idx: int) -> Bytes:
        start = 0
        if idx > 0:
            start = list(self.sorted.values())[idx - 1]["position"] + 1

        stop = len(self.src)
        if idx < len(self.sorted):
            stop = list(self.sorted.values())[idx]["position"]

        chunk = self.src[start:stop]
        return Bytes(chunk)

    def sig_tmpl():
        # We encode the app id as an 8 byte integer to ensure its a known size
        # Otherwise the uvarint encoding may produce a different byte offset
        # for the template variables
        admin_app_id = Tmpl.Int("TMPL_APP_ID")
        seed_amt = Tmpl.Int("TMPL_SEED_AMT")
    
        @Subroutine(TealType.uint64)
        def init():
            algo_seed = Gtxn[0]
            optin = Gtxn[1]
    
            return And(
                Global.group_size() == Int(2),
                algo_seed.type_enum() == TxnType.Payment,
                algo_seed.amount() == seed_amt,
                algo_seed.rekey_to() == Global.zero_address(),
                algo_seed.close_remainder_to() == Global.zero_address(),
                optin.type_enum() == TxnType.ApplicationCall,
                optin.on_completion() == OnComplete.OptIn,
                optin.application_id() == admin_app_id,
                optin.rekey_to() == Global.zero_address(),
            )
    
        return Seq(
            # Just putting adding this as a tmpl var to make the address unique and deterministic
            # We don't actually care what the value is, pop it
            Pop(Tmpl.Int("TMPL_ADDR_IDX")),
            Pop(Tmpl.Bytes("TMPL_EMITTER_ID")),
            init(),
        )
    
    def get_sig_tmpl(**kwargs):
        return compileTeal(
            sig_tmpl(**kwargs), mode=Mode.Signature, version=5, assembleConstants=True
        )


class Account:
    """Represents a private key and address for an Algorand account"""

    def __init__(self, privateKey: str) -> None:
        self.sk = privateKey
        self.addr = account.address_from_private_key(privateKey)
        print (privateKey + " -> " + self.getMnemonic())

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

class Token:
    def __init__(self) -> None:
        self.ALGOD_ADDRESS = "http://localhost:4001"
        self.ALGOD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.FUNDING_AMOUNT = 100_000_000

        self.KMD_ADDRESS = "http://localhost:4002"
        self.KMD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.KMD_WALLET_NAME = "unencrypted-default-wallet"
        self.KMD_WALLET_PASSWORD = ""

        self.seed_amt = int(1001000)  # The black magic in this number... 
        self.cache = {}

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
            sks = [account.generate_account()[0] for i in range(3)]
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

    def getBalances(self, client: AlgodClient, account: str) -> Dict[int, int]:
        balances: Dict[int, int] = dict()
    
        accountInfo = client.account_info(account)
    
        # set key 0 to Algo balance
        balances[0] = accountInfo["amount"]
    
        assets: List[Dict[str, Any]] = accountInfo.get("assets", [])
        for assetHolding in assets:
            assetID = assetHolding["asset-id"]
            amount = assetHolding["amount"]
            balances[assetID] = amount
    
        return balances

    def fullyCompileContract(self, client: AlgodClient, contract: Expr) -> bytes:
        teal = compileTeal(contract, mode=Mode.Application, version=5)
        response = client.compile(teal)
        return response

    # helper function that formats global state for printing
    def format_state(self, state):
        formatted = {}
        for item in state:
            key = item['key']
            value = item['value']
            formatted_key = base64.b64decode(key).decode('utf-8')
            if value['type'] == 1:
                # byte string
                if formatted_key == 'voted':
                    formatted_value = base64.b64decode(value['bytes']).decode('utf-8')
                else:
                    formatted_value = value['bytes']
                formatted[formatted_key] = formatted_value
            else:
                # integer
                formatted[formatted_key] = value['uint']
        return formatted
    
    # helper function to read app global state
    def read_global_state(self, client, addr, app_id):
        results = client.account_info(addr)
        apps_created = results['created-apps']
        for app in apps_created:
            if app['id'] == app_id and 'global-state' in app['params']:
                return self.format_state(app['params']['global-state'])
        return {}

    def read_state(self, client, addr, app_id):
        results = client.account_info(addr)
        apps_created = results['created-apps']
        for app in apps_created:
            if app['id'] == app_id:
                return app
        return {}

    def getPrimaryContracts(self, 
                            client: AlgodClient,
                            seed_amt: int = 0,
                            tmpl_sig: TmplSig = None,
                            ) -> Tuple[bytes, bytes]:

        def vaa_processor_program(seed_amt: int, tmpl_sig: TmplSig):
            blob = LocalBlob()

            @Subroutine(TealType.bytes)
            def encode_uvarint(val: TealType.uint64, b: TealType.bytes):
                buff = ScratchVar()
                return Seq(
                    buff.store(b),
                    Concat(
                        buff.load(),
                        If(
                            val >= Int(128),
                            encode_uvarint(
                                val >> Int(7),
                                Extract(Itob((val & Int(255)) | Int(128)), Int(7), Int(1)),
                            ),
                            Extract(Itob(val & Int(255)), Int(7), Int(1)),
                        ),
                    ),
                )
    
            @Subroutine(TealType.bytes)
            def get_sig_address(acct_seq_start: TealType.uint64, emitter: TealType.bytes):
                # We could iterate over N items and encode them for a more general interface
                # but we inline them directly here
        
                return Sha512_256(
                    Concat(
                        Bytes("Program"),
                        # ADDR_IDX aka sequence start
                        tmpl_sig.get_bytecode_chunk(0),
                        encode_uvarint(acct_seq_start, Bytes("")),
                        # EMMITTER_ID
                        tmpl_sig.get_bytecode_chunk(1),
                        encode_uvarint(Len(emitter), Bytes("")),
                        emitter,
                        # SEED_AMT
                        tmpl_sig.get_bytecode_chunk(2),
                        encode_uvarint(Int(seed_amt), Bytes("")),
                        # APP_ID
                        tmpl_sig.get_bytecode_chunk(3),
                        encode_uvarint(Global.current_application_id(), Bytes("")),
                        tmpl_sig.get_bytecode_chunk(4),
                    )
                )
        
            @Subroutine(TealType.uint64)
            def optin():
                # Alias for readability
                algo_seed = Gtxn[0]
                optin = Gtxn[1]
        
                well_formed_optin = And(
                    # Check that we're paying it
                    algo_seed.type_enum() == TxnType.Payment,
                    algo_seed.amount() == Int(seed_amt),
                    # Check that its an opt in to us
                    optin.type_enum() == TxnType.ApplicationCall,
                    optin.on_completion() == OnComplete.OptIn,
                    # Not strictly necessary since we wouldn't be seeing this unless it was us, but...
                    optin.application_id() == Global.current_application_id(),
                )
        
                return Seq(
                    # Make sure its a valid optin
                    Assert(well_formed_optin),
                    # Init by writing to the full space available for the sender (Int(0))
                    blob.zero(Int(0)),
                    # we gucci
                    Int(1)
                )
        
            def nop():
                return Seq([Approve()])

            @Subroutine(TealType.none)
            def checkForDuplicate():
                off = ScratchVar()
                emitter = ScratchVar()
                sequence = ScratchVar()
                b = ScratchVar()
                byte_offset = ScratchVar()

                return Seq(
                    off.store(Btoi(Extract(Txn.application_args[1], Int(5), Int(1))) * Int(66) + Int(16)), # The offset of the emitter
                    emitter.store(Extract(Txn.application_args[1], off.load(), Int(32))),
                    sequence.store(Btoi(Extract(Txn.application_args[1], off.load() + Int(32), Int(8)))),
                    byte_offset.store(sequence.load() / Int(max_bits)),
                    # They passed us the correct account?
                    Assert(Txn.accounts[1] == get_sig_address(byte_offset.load(), emitter.load())),
                    # Now, lets go grab the raw byte
                    b.store(blob.get_byte(Int(1), byte_offset.load())),

                    # TODO
                    # I would hope we've never seen this packet before...   throw an exception if we have?
                    Assert(GetBit(b.load(), sequence.load() % Int(8)) == Int(0)),

                    # Lets mark this bit so that we never see it again
                    blob.set_byte(Int(1), byte_offset.load(), SetBit(b.load(), sequence.load() % Int(8), Int(1)))
                )
            
            def hdlGovernance():
                off = ScratchVar()
                a = ScratchVar()
                emitter = ScratchVar()
                idx = ScratchVar()
                len = ScratchVar()

                return Seq([
                    off.store(Btoi(Extract(Txn.application_args[1], Int(5), Int(1))) * Int(66) + Int(14)), # The offset of the chain
                    # Correct chain? 
                    Assert(Extract(Txn.application_args[1], off.load(), Int(2)) == Bytes("base16", "0001")),
                    # Correct emitter?
                    Assert(Extract(Txn.application_args[1], off.load() + Int(2), Int(32)) == Bytes("base16", "0000000000000000000000000000000000000000000000000000000000000004")),
                    # Get us to the payload
                    off.store(off.load() + Int(43)),
                    # Is this a governance message?
                    Assert(Extract(Txn.application_args[1], off.load(), Int(32)) == Bytes("base16", "00000000000000000000000000000000000000000000000000000000436f7265")),
                    off.store(off.load() + Int(32)),
                    a.store(Btoi(Extract(Txn.application_args[1], off.load(), Int(1)))),
                    Cond( 
                        [a.load() == Int(1), Seq([
                            # ContractUpgrade is a VAA that instructs an implementation on a specific chain to upgrade itself
                            # 
                            # In the case of Algorand, it contains the hash of the program that we are allowed to upgrade ourselves to.  We would then run the upgrade program itself
                            # to perform the actual upgrade
                            Assert(Extract(Txn.application_args[1], off.load() + Int(1), Int(2)) == Bytes("base16", "0008")),
                            off.store(off.load() + Int(3)),
                            App.globalPut(Bytes("validUpdateApproveHash"), Extract(Txn.application_args[1], off.load(), Int(32)))
                        ])],
                        [a.load() == Int(2), Seq([
                            # We are updating the guardian set

                            # TODO: Should these be pointed at all chains or could this just be us?
                            Assert(Extract(Txn.application_args[1], off.load() + Int(1), Int(2)) == Bytes("base16", "0000")),
                            # move off to point at the NewGuardianSetIndex
                            off.store(off.load() + Int(3)),
                            idx.store(Btoi(Extract(Txn.application_args[1], off.load(), Int(4)))),
                            # Lets see if the user handed us the correct memory
                            Assert(Txn.accounts[3] == get_sig_address(idx.load(), Bytes("guardian"))), 
                            off.store(off.load() + Int(4)),
                            # Send all the guardians over...
                            # How many signatures do we have?
                            len.store(Btoi(Extract(Txn.application_args[1], off.load(), Int(1)))),
                            Pop(blob.write(Int(3), Int(0), Extract(Txn.application_args[1], off.load(), Int(1) + (Int(20) * len.load()))))
                        ])]
                         ),
                    Approve()
                ])

            def init():
                return Seq([
                    Assert(Txn.sender() == Global.creator_address()),
                    # TODO:  Is this supposed to assert or just return silently?  Silently ignoring duplicates would be better for parallel relays...
                    checkForDuplicate(),
                    hdlGovernance()
                ])

            METHOD = Txn.application_args[0]

            on_delete = Seq([Reject()])

            router = Cond(
                [METHOD == Bytes("nop"), nop()],
                [METHOD == Bytes("init"), init()],
            )

            on_create = Seq( [
                App.globalPut(Bytes("validUpdateApproveHash"), Bytes("")),
                App.globalPut(Bytes("validUpdateClearHash"), Bytes("BJATCHES5YJZJ7JITYMVLSSIQAVAWBQRVGPQUDT5AZ2QSLDSXWWM46THOY")), # empty clear state program
                Return(Int(1))
            ])

            on_update = Seq( [
                Assert(Sha512_256(Concat(Bytes("Program"), Txn.approval_program())) == App.globalGet(Bytes("validUpdateApproveHash"))),
                Assert(Sha512_256(Concat(Bytes("Program"), Txn.clear_state_program())) == App.globalGet(Bytes("validUpdateClearHash"))),
                Return(Int(1))
            ] )

            on_optin = Seq( [
                Return(optin())
            ])

            return Cond(
                [Txn.application_id() == Int(0), on_create],
                [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
                [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
#                [Txn.on_completion() == OnComplete.CloseOut, Int(0)],
               [Txn.on_completion() == OnComplete.OptIn, on_optin],
               [Txn.on_completion() == OnComplete.NoOp, router]
            )
        
        def clear_state_program():
            return Int(1)
    
        APPROVAL_PROGRAM = self.fullyCompileContract(client, vaa_processor_program(seed_amt, tmpl_sig))
        CLEAR_STATE_PROGRAM = self.fullyCompileContract(client, clear_state_program())

        return APPROVAL_PROGRAM, CLEAR_STATE_PROGRAM


    def createTokenApp(
        self,
        client: AlgodClient,
        sender: Account,
    ) -> int:
        # reads from sig.json
        self.tsig = TmplSig("sig")

        approval, clear = self.getPrimaryContracts(client, seed_amt=self.seed_amt, tmpl_sig=self.tsig)

        pprint.pprint(clear)
    
        globalSchema = transaction.StateSchema(num_uints=40, num_byte_slices=6)
        localSchema = transaction.StateSchema(num_uints=0, num_byte_slices=16)
    
        app_args = [ ]
    
        txn = transaction.ApplicationCreateTxn(
            sender=sender.getAddress(),
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=b64decode(approval["result"]),
            clear_program=b64decode(clear["result"]),
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

    def account_exists(self, client, app_id, addr):
        try:
            ai = client.account_info(addr)
            pprint.pprint(ai)
            if "apps-local-state" not in ai:
                return False
    
            for app in ai["apps-local-state"]:
                if app["id"] == app_id:
                    return True
        except:
            print("Failed to find account {}".format(addr))
        return False

    def optin(self, client, sender, app_id, idx, emitter):
        print ((app_id, idx, emitter))

        lsa = self.tsig.populate(
            {
                "TMPL_SEED_AMT": self.seed_amt,
                "TMPL_APP_ID": app_id,
                "TMPL_ADDR_IDX": idx,
                "TMPL_EMITTER_ID": emitter,
            }
        )

        sig_addr = lsa.address()

        if sig_addr not in self.cache and not self.account_exists(client, app_id, sig_addr):
            # Create it
            sp = client.suggested_params()

            seed_txn = transaction.PaymentTxn(sender = sender.getAddress(), sp = sp, receiver = sig_addr, amt = self.seed_amt)
            optin_txn = transaction.ApplicationOptInTxn(sig_addr, sp, app_id)

            transaction.assign_group_id([seed_txn, optin_txn])

            signed_seed = seed_txn.sign(sender.getPrivateKey())
            signed_optin = transaction.LogicSigTransaction(optin_txn, lsa)

            client.send_transactions([signed_seed, signed_optin])
            txn = self.waitForTransaction(client, signed_optin.get_txid()).__dict__
            
            self.cache[sig_addr] = True

        return sig_addr

    def parseVAA(self, vaa):
        print (vaa.hex())
        ret = {"version": int.from_bytes(vaa[0:1], "big"), "index": int.from_bytes(vaa[1:4], "big"), "siglen": int.from_bytes(vaa[5:6], "big")}
        for i in range(ret["siglen"]):
            ret["sig" + str(i)] = vaa[(6 + (i * 66)):(6 + (i * 66)) + 66]
        off = (ret["siglen"] * 66) + 6
        ret["timestamp"] = int.from_bytes(vaa[off:(off + 4)], "big")
        off += 4
        ret["nonce"] = int.from_bytes(vaa[off:(off + 4)], "big")
        off += 4
        ret["chain"] = int.from_bytes(vaa[off:(off + 2)], "big")
        off += 2
        ret["emitter"] = vaa[off:(off + 32)]
        off += 32
        ret["sequence"] = int.from_bytes(vaa[off:(off + 8)], "big")
        off += 8
        ret["consistency"] = int.from_bytes(vaa[off:(off + 1)], "big")
        off += 1
        ret["payload"] = vaa[off:].hex()

        if vaa[off:(off + 32)].hex() == "00000000000000000000000000000000000000000000000000000000436f7265":
            ret["module"] = vaa[off:(off + 32)].hex()
            off += 32
            ret["action"] = int.from_bytes(vaa[off:(off + 1)], "big")
            off += 1
            ret["targetChain"] = int.from_bytes(vaa[off:(off + 2)], "big")
            off += 2
            ret["NewGuardianSetIndex"] = int.from_bytes(vaa[off:(off + 4)], "big")
            off += 4
        
        return ret

    def bootGuardians(self, vaa, client, sender, appid):
        p = self.parseVAA(vaa)
        if "NewGuardianSetIndex" not in p:
            raise Exception("invalid guardian VAA")
        pprint.pprint(p)

        seq_addr = self.optin(client, sender, appid, int(p["sequence"] / max_bits), p["emitter"].hex())
        guardian_addr = self.optin(client, sender, appid, p["index"], b"guardian".hex())
        newguardian_addr = self.optin(client, sender, appid, p["NewGuardianSetIndex"], b"guardian".hex())

        print("opted in to everything")

        # wormhole is not a cheap protocol... we need to buy ourselves
        # some extra CPU cycles by having an early txn do nothing.
        # This leaves cycles over for later txn's in the same group

        txn0 = transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"nop", b"0"],
            sp=client.suggested_params(),
        )

        txn1 = transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"nop", b"1"],
            sp=client.suggested_params(),
        )

        txn2 = transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"init", vaa],
            accounts=[seq_addr, guardian_addr, newguardian_addr],
            sp=client.suggested_params(),
        )

        transaction.assign_group_id([txn0, txn1, txn2])
    
        signedTxn0 = txn0.sign(sender.getPrivateKey())
        signedTxn1 = txn1.sign(sender.getPrivateKey())
        signedTxn2 = txn2.sign(sender.getPrivateKey())

        client.send_transactions([signedTxn0, signedTxn1, signedTxn2])
        response = self.waitForTransaction(client, signedTxn2.get_txid())
        pprint.pprint(response.__dict__)
        
        sys.exit(0)

    def simple_token(self):
        client = self.getAlgodClient()

        print("Generating the foundation account...")
        foundation = self.getTemporaryAccount(client)

        print("Creating the Token app")
        appID = self.createTokenApp(client=client, sender=foundation)
        print("appID = " + str(appID))

        # This sets the guardians
        bootVAA = bytes.fromhex(open("boot.vaa", "r").read())

        self.bootGuardians(bootVAA, client, foundation, appID)

        player = self.getTemporaryAccount(client)

        pprint.pprint(self.read_state(client, foundation.getAddress(), appID))

token = Token()
token.simple_token()
