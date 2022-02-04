# python3 -m pip install -I pycryptodomex

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
from portalCore import getCoreContracts
from TmplSig import TmplSig

from algosdk.v2client.algod import AlgodClient
from algosdk.kmd import KMDClient
from algosdk import account, mnemonic
from algosdk.encoding import decode_address
from algosdk.future import transaction
from pyteal import compileTeal, Mode, Expr
from pyteal import *
from algosdk.logic import get_application_address
from vaa_verify import get_vaa_verify

from Cryptodome.Hash import keccak

from algosdk.future.transaction import LogicSig

import pprint

max_keys = 16
max_bytes_per_key = 127
bits_per_byte = 8

bits_per_key = max_bytes_per_key * bits_per_byte
max_bytes = max_bytes_per_key * max_keys
max_bits = bits_per_byte * max_bytes

class Account:
    """Represents a private key and address for an Algorand account"""

    def __init__(self, privateKey: str) -> None:
        self.sk = privateKey
        self.addr = account.address_from_private_key(privateKey)
        #print (privateKey + " -> " + self.getMnemonic())

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

class PortalCore:
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

    def createPortalCoreApp(
        self,
        client: AlgodClient,
        sender: Account,
    ) -> int:
        # reads from sig.json
        self.tsig = TmplSig("sig")

        approval, clear = getCoreContracts(client, seed_amt=self.seed_amt, tmpl_sig=self.tsig)

        globalSchema = transaction.StateSchema(num_uints=4, num_byte_slices=4)
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
            if "apps-local-state" not in ai:
                return False
    
            for app in ai["apps-local-state"]:
                if app["id"] == app_id:
                    return True
        except:
            print("Failed to find account {}".format(addr))
        return False

    def optin(self, client, sender, app_id, idx, emitter, doCreate=True):
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
            if doCreate:
                # Create it
                sp = client.suggested_params()
    
                seed_txn = transaction.PaymentTxn(sender = sender.getAddress(), sp = sp, receiver = sig_addr, amt = self.seed_amt)
                optin_txn = transaction.ApplicationOptInTxn(sig_addr, sp, app_id)
    
                transaction.assign_group_id([seed_txn, optin_txn])
    
                signed_seed = seed_txn.sign(sender.getPrivateKey())
                signed_optin = transaction.LogicSigTransaction(optin_txn, lsa)
    
                client.send_transactions([signed_seed, signed_optin])
                self.waitForTransaction(client, signed_optin.get_txid())
                
                self.cache[sig_addr] = True

        return sig_addr

    def parseVAA(self, vaa):
#        print (vaa.hex())
        ret = {"version": int.from_bytes(vaa[0:1], "big"), "index": int.from_bytes(vaa[1:5], "big"), "siglen": int.from_bytes(vaa[5:6], "big")}
        ret["signatures"] = vaa[6:(ret["siglen"] * 66) + 6]
        ret["sigs"] = []
        for i in range(ret["siglen"]):
            ret["sigs"].append(vaa[(6 + (i * 66)):(6 + (i * 66)) + 66].hex())
        off = (ret["siglen"] * 66) + 6
        ret["digest"] = vaa[off:]  # This is what is actually signed...
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

        seq_addr = self.optin(client, sender, appid, int(p["sequence"] / max_bits), p["emitter"].hex())
        guardian_addr = self.optin(client, sender, appid, p["index"], b"guardian".hex())
        newguardian_addr = self.optin(client, sender, appid, p["NewGuardianSetIndex"], b"guardian".hex())

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
            app_args=[b"init", vaa, decode_address(self.vaa_verify["hash"])],
            accounts=[seq_addr, guardian_addr, newguardian_addr],
            sp=client.suggested_params(),
        )

        transaction.assign_group_id([txn0, txn1, txn2])
    
        signedTxn0 = txn0.sign(sender.getPrivateKey())
        signedTxn1 = txn1.sign(sender.getPrivateKey())
        signedTxn2 = txn2.sign(sender.getPrivateKey())

        client.send_transactions([signedTxn0, signedTxn1, signedTxn2])
        response = self.waitForTransaction(client, signedTxn2.get_txid())
        #pprint.pprint(response.__dict__)


    def lookupGuardians(self, client, sender, appid, index):
        newguardian_addr = self.optin(client, sender, appid, index, b"guardian".hex(), False)

        app_state = None
        ai = client.account_info(newguardian_addr)
        for app in ai["apps-local-state"]:
            if app["id"] == appid:
                app_state = app["key-value"]

        ret = b''
        if None != app_state:
            vals = {}
            e = bytes.fromhex("00"*127)
            for kv in app_state:
                key = int.from_bytes(base64.b64decode(kv["key"]), "big")
                v = base64.b64decode(kv["value"]["bytes"])
                if v != e:
                    vals[key] = v
            for k in sorted(vals.keys()):
                ret = ret + vals[k]
        return ret

    # There is no client side duplicate suppression, error checking, or validity
    # checking. We need to be able to detect all failure cases in
    # the contract itself and we want to use this to drive the failure test
    # cases

    def submitVAA(self, vaa, client, sender, appid):
        p = self.parseVAA(vaa)

        # First we need to opt into the sequence number 
        seq_addr = self.optin(client, sender, appid, int(p["sequence"] / max_bits), p["emitter"].hex())
        # And then the signatures to help us verify the vaa_s
        guardian_addr = self.optin(client, sender, appid, p["index"], b"guardian".hex())

        accts = [seq_addr, guardian_addr]

        # If this happens to be setting up a new guardian set, we probably need it as well...
        if "NewGuardianSetIndex" in p:
            newguardian_addr = self.optin(client, sender, appid, p["NewGuardianSetIndex"], b"guardian".hex())
            accts.append(newguardian_addr)

        keys = self.lookupGuardians(client, sender, appid, p["index"])

        sp = client.suggested_params()

        txns = []

        # Right now there is not really a good way to estimate the fees,
        # in production, on a conjested network, how much verifying
        # the signatures is going to cost.

        # So, what we do instead
        # is we top off the verifier back up to 2A so effectively we
        # are paying for the previous persons verification which on a
        # unconjested network should be the exact same cost as our
        # transaction.. 

        # I guess it is possible for a hacker to eliminate this step
        # and save themselves a dollar over the course of a bunch of
        # redemptions...   I can sleep at night with this

        pmt = 3000
        bal = self.getBalances(client, self.vaa_verify["hash"])
        if ((200000 - bal[0]) >= pmt):
            pmt = 200000 - bal[0]

        print("Sending %d algo to cover fees" % (pmt))
        txns.append(
            transaction.PaymentTxn(
                sender = sender.getAddress(), 
                sp = sp, 
                receiver = self.vaa_verify["hash"], 
                amt = pmt
            )
        )

        # How many signatures can we process in a single txn
        bsize = (9*66)
        blocks = int(len(p["signatures"]) / bsize) + 1

        # We don't pass the entire payload in but instead just pass it pre digested.  This gets around size
        # limitations with lsigs AND reduces the cost of the entire operation on a conjested network
        digest = keccak.new(digest_bits=256).update(keccak.new(digest_bits=256).update(p["digest"]).digest()).digest()

        for i in range(blocks):
            # Which signatures will we be verifying in this block
            sigs = p["signatures"][(i * bsize):]
            if (len(sigs) > bsize):
                sigs = sigs[:bsize]
            # keys
            k = b''
            # Grab the key associated the signature
            for q in range(int(len(sigs) / 66)):
                # Which guardian is this signature associated with
                g = sigs[q * 66]
                key = keys[((g * 20) + 1) : (((g + 1) * 20) + 1)]
                k = k + key

            txns.append(transaction.ApplicationCallTxn(
                    sender=self.vaa_verify["hash"],
                    index=appid,
                    on_complete=transaction.OnComplete.NoOpOC,
                    app_args=[b"verifySigs", sigs, k, digest],
                    accounts=accts,
                    sp=sp
                ))

        txns.append(transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"verifyVAA", vaa],
            accounts=accts,
            note = p["digest"],
            sp=sp
        ))

        txns.append(transaction.ApplicationCallTxn(
            sender=sender.getAddress(),
            index=appid,
            on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"governance", vaa],
            accounts=accts,
            note = p["digest"],
            sp=sp
        ))

        transaction.assign_group_id(txns)

        grp = []
        pk = sender.getPrivateKey()
        for t in txns:
            if ("app_args" in t.__dict__ and len(t.app_args) > 0 and t.app_args[0] == b"verifySigs"):
                grp.append(transaction.LogicSigTransaction(t, self.vaa_verify["lsig"]))
            else:
                grp.append(t.sign(pk))

        client.send_transactions(grp)
        response = self.waitForTransaction(client, grp[-2].get_txid())
        pprint.pprint(response.__dict__)

    def simple_core(self):
        client = self.getAlgodClient()

        print("building our stateless vaa_verify...")
        self.vaa_verify = client.compile(get_vaa_verify())
        self.vaa_verify["lsig"] = LogicSig(base64.b64decode(self.vaa_verify["result"]))
        print(self.vaa_verify["hash"])
        print("")

        print("Generating the foundation account...")
        foundation = self.getTemporaryAccount(client)
        print(foundation.getAddress())
        print("")

        print("Creating the PortalCore app")
        appID = self.createPortalCoreApp(client=client, sender=foundation)
        print("appID = " + str(appID))

        print("bootstrapping the guardian set...")
        bootVAA = bytes.fromhex(open("boot.vaa", "r").read())
        self.bootGuardians(bootVAA, client, foundation, appID)

        print("grabbing a untrusted account")
        player = self.getTemporaryAccount(client)
        print(player.getAddress())
        print("")

        print("upgrading the the guardian set using untrusted account...")
        upgradeVAA = bytes.fromhex(open("boot2.vaa", "r").read())

        self.submitVAA(upgradeVAA, client, player, appID)

        #pprint.pprint(self.lookupGuardians(client, player, appID, 1))

        #pprint.pprint(self.read_state(client, foundation.getAddress(), appID))

core = PortalCore()
core.simple_core()
