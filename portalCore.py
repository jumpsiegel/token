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
from TmplSig import TmplSig

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

def fullyCompileContract(client: AlgodClient, contract: Expr) -> bytes:
    teal = compileTeal(contract, mode=Mode.Application, version=5)
    response = client.compile(teal)
    return response

def getCoreContracts(   client: AlgodClient,
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

                        # This should point at all chains
                        Assert(Extract(Txn.application_args[1], off.load() + Int(1), Int(2)) == Bytes("base16", "0000")),

                        # move off to point at the NewGuardianSetIndex and grab it
                        off.store(off.load() + Int(3)),
                        idx.store(Btoi(Extract(Txn.application_args[1], off.load(), Int(4)))),

                        # Lets see if the user handed us the correct memory... no hacky hacky
                        Assert(Txn.accounts[3] == get_sig_address(idx.load(), Bytes("guardian"))), 

                        # Write everything out to the auxilliary storage
                        off.store(off.load() + Int(4)),
                        len.store(Btoi(Extract(Txn.application_args[1], off.load(), Int(1)))),
                        Pop(blob.write(Int(3), Int(0), Extract(Txn.application_args[1], off.load(), Int(1) + (Int(20) * len.load()))))
                    ])]
                     ),
                Approve()
            ])

        def init():
            return Seq([
                # You own it, you better never let it go
                Assert(Txn.sender() == Global.creator_address()),

                # You only get one shot, do not miss your chance to blow
                Assert(App.globalGet(Bytes("booted")) != Bytes("true")),
                App.globalPut(Bytes("booted"), Bytes("true")),

                # This opportunity comes once in a lifetime
                App.globalPut(Bytes("vphash"), Txn.application_args[2]),

                # yo
                hdlGovernance()
            ])

        METHOD = Txn.application_args[0]

        on_delete = Seq([Reject()])

        router = Cond(
            [METHOD == Bytes("nop"), nop()],
            [METHOD == Bytes("init"), init()],
        )

        on_create = Seq( [
            App.globalPut(Bytes("booted"), Bytes("false")),
            App.globalPut(Bytes("vphash"), Bytes("")),
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

    APPROVAL_PROGRAM = fullyCompileContract(client, vaa_processor_program(seed_amt, tmpl_sig))
    CLEAR_STATE_PROGRAM = fullyCompileContract(client, clear_state_program())

    return APPROVAL_PROGRAM, CLEAR_STATE_PROGRAM
