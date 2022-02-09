#!/usr/bin/python3
"""
Copyright 2022 Wormhole Project Contributors

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

from typing import List, Tuple, Dict, Any, Optional, Union

from pyteal.ast import *
from pyteal.types import *
from pyteal.compiler import *
from pyteal.ir import *
from globals import *
from inlineasm import *

from algosdk.v2client.algod import AlgodClient

from TmplSig import TmplSig

from local_blob import LocalBlob

import sys

def fullyCompileContract(client: AlgodClient, contract: Expr) -> bytes:
    teal = compileTeal(contract, mode=Mode.Application, version=5)
    response = client.compile(teal)
    return response

def clear_token_bridge():
    return Int(1)

def approve_token_bridge(seed_amt: int, tmpl_sig: TmplSig):
    blob = LocalBlob()

    @Subroutine(TealType.bytes)
    def extract_value(id) -> Expr:
        maybe = AssetParam.url(id)
    
        return Seq(maybe, Assert(maybe.hasValue()), maybe.value())
    
    
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
    def trim_bytes(str: TealType.bytes):
        len = ScratchVar()
        off = ScratchVar()
        zero = ScratchVar()
        r = ScratchVar()

        return Seq([
            r.store(str),

            len.store(Len(r.load())),
            zero.store(BytesZero(Int(1))),
            off.store(Int(0)),

            While(off.load() < len.load()).Do(Seq([
                If(Extract(r.load(), off.load(), Int(1)) == zero.load()).Then(Seq([
                        r.store(Extract(r.load(), Int(0), off.load())),
                        off.store(len.load())
                ])),
                off.store(off.load() + Int(1))
            ])),
            r.load()
        ])

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
    
    def attest():
        me = Global.current_application_address()
        off = ScratchVar()
    
        Address = ScratchVar()
        Chain = ScratchVar()
        Decimals = ScratchVar()
        Symbol = ScratchVar()
        Name = ScratchVar()

        asset = ScratchVar()
    
        return Seq([
            Assert(And(
                # Lets see if the vaa we are about to process was actually verified by the core
                Gtxn[Txn.group_index() - Int(2)].type_enum() == TxnType.ApplicationCall,
                Gtxn[Txn.group_index() - Int(2)].application_id() == App.globalGet(Bytes("coreid")),
                Gtxn[Txn.group_index() - Int(2)].application_args[0] == Bytes("verifyVAA"),
                Gtxn[Txn.group_index() - Int(2)].sender() == Txn.sender(),
                Gtxn[Txn.group_index() - Int(2)].rekey_to() == Global.zero_address(),
                Gtxn[Txn.group_index() - Int(2)].application_args[1] == Txn.application_args[1],

                # We all opted into the same accounts?
                Gtxn[Txn.group_index() - Int(2)].accounts[0] == Txn.accounts[0],
                Gtxn[Txn.group_index() - Int(2)].accounts[1] == Txn.accounts[1],
                Gtxn[Txn.group_index() - Int(2)].accounts[2] == Txn.accounts[2],
    
                # Did the user pay us attest a new product?
                Gtxn[Txn.group_index() - Int(1)].type_enum() == TxnType.Payment,
                Gtxn[Txn.group_index() - Int(1)].amount() >= Int(200000),
                Gtxn[Txn.group_index() - Int(1)].sender() == Txn.sender(),
                Gtxn[Txn.group_index() - Int(1)].receiver() == me,
                Gtxn[Txn.group_index() - Int(1)].rekey_to() == Global.zero_address(),
    
                (Global.group_size() - Int(1)) == Txn.group_index()    # This should be the last entry...
            )),

            off.store(Btoi(Extract(Txn.application_args[1], Int(5), Int(1))) * Int(66) + Int(6) + Int(8)), # The offset of the chain
            Chain.store(Btoi(Extract(Txn.application_args[1], off.load(), Int(2)))),
            off.store(off.load()+Int(43)),
    
            Assert(Int(2) ==      Btoi(Extract(Txn.application_args[1], off.load(),           Int(1)))),
            Address.store(             Extract(Txn.application_args[1], off.load() + Int(1),  Int(32))),
    
            # Has the nice effect of ALSO testing we are looking at the correct object..
            Assert(Chain.load()== Btoi(Extract(Txn.application_args[1], off.load() + Int(33), Int(2)))),
            Decimals.store(       Btoi(Extract(Txn.application_args[1], off.load() + Int(35), Int(1)))),
            Symbol.store(              Extract(Txn.application_args[1], off.load() + Int(36), Int(32))),
            Name.store(                Extract(Txn.application_args[1], off.load() + Int(68), Int(32))),

            # This pass?!  Actually kind of shocked....  maybe I know what I am doing?!
            Assert(Txn.accounts[3] == get_sig_address(Chain.load(), Address.load())),

            # Lets see if we've seen this asset before
            asset.store(blob.read(Int(3), Int(0), Int(8))),

            If(asset.load() == Itob(Int(0))).Then(Seq([
                InnerTxnBuilder.Begin(),
                InnerTxnBuilder.SetFields(
                    {
                        TxnField.type_enum: TxnType.AssetConfig,
                        TxnField.config_asset_name: trim_bytes(Name.load()),        # TODO: ??
                        TxnField.config_asset_unit_name: trim_bytes(Symbol.load()), # TODO: ??
                        TxnField.config_asset_total: Int(int(1e17)),
                        TxnField.config_asset_decimals: Decimals.load(),
                        TxnField.config_asset_manager: me,
                        TxnField.config_asset_freeze: me,
                        TxnField.config_asset_clawback: me,
                        TxnField.config_asset_reserve: me,
                        # TODO: It would be really nice if we could do base encoding... can that be done in pyteal?
                        TxnField.config_asset_url: Concat(Itob(Chain.load()), Address.load()),
                        TxnField.fee: Int(0),
                    }
                ),
                InnerTxnBuilder.Submit(),

                asset.store(Itob(InnerTxn.created_asset_id())),
                Pop(blob.write(Int(3), Int(0), asset.load())),
                Log(asset.load())   # Pass back the algorand asset id for fun
            ])).Else(Seq([
                Log(Bytes("This looks familiar")),
                Log(extract_value(Btoi(asset.load())))
            ])),
    
            Approve()
        ])

    METHOD = Txn.application_args[0]

    on_delete = Seq([Reject()])

    router = Cond(
        [METHOD == Bytes("attest"), attest()],
    )

    on_create = Seq( [
        App.globalPut(Bytes("coreid"), Btoi(Txn.application_args[0])),
        App.globalPut(Bytes("validUpdateApproveHash"), Bytes("")),
        App.globalPut(Bytes("validUpdateClearHash"), Bytes("BJATCHES5YJZJ7JITYMVLSSIQAVAWBQRVGPQUDT5AZ2QSLDSXWWM46THOY")), # empty clear state program
        Return(Int(1))
    ])

    on_update = Seq( [
        Assert(Sha512_256(Concat(Bytes("Program"), Txn.approval_program())) == App.globalGet(Bytes("validUpdateApproveHash"))),
        Assert(Sha512_256(Concat(Bytes("Program"), Txn.clear_state_program())) == App.globalGet(Bytes("validUpdateClearHash"))),
        Return(Int(1))
    ] )

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

    on_optin = Seq( [
        Return(optin())
    ])

    return Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
        [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
        [Txn.on_completion() == OnComplete.OptIn, on_optin],
        [Txn.on_completion() == OnComplete.NoOp, router]
    )

def get_token_bridge(client: AlgodClient, seed_amt: int = 0, tmpl_sig: TmplSig = None) -> Tuple[bytes, bytes]:
    APPROVAL_PROGRAM = fullyCompileContract(client, approve_token_bridge(seed_amt, tmpl_sig))
    CLEAR_STATE_PROGRAM = fullyCompileContract(client, clear_token_bridge())

    return APPROVAL_PROGRAM, CLEAR_STATE_PROGRAM

# 
# 
# 
# 
#     @Subroutine(TealType.none)
#     def axfer(reciever: TealType.bytes, aid: TealType.uint64, amt: TealType.uint64):
#         return Seq(
#             InnerTxnBuilder.Begin(),
#             InnerTxnBuilder.SetFields(
#                 {
#                     TxnField.type_enum: TxnType.AssetTransfer,
#                     TxnField.xfer_asset: aid,
#                     TxnField.asset_amount: amt,
#                     TxnField.asset_receiver: reciever,
#                     TxnField.fee: Int(0),
#                 }
#             ),
#             InnerTxnBuilder.Submit(),
#         )
# 
#     @Subroutine(TealType.none)
#     def pay(receiver: TealType.bytes, amt: TealType.uint64):
#         return Seq(
#             InnerTxnBuilder.Begin(),
#             InnerTxnBuilder.SetFields(
#                 {
#                     TxnField.type_enum: TxnType.Payment,
#                     TxnField.amount: amt,
#                     TxnField.receiver: receiver,
#                     TxnField.fee: Int(0),
#                 }
#             ),
#             InnerTxnBuilder.Submit(),
#         )
# 
#         return Seq(
#             pool_token_check,
#             # Make sure we've not already set this
#             Assert(Not(pool_token_check.hasValue())),
#             Assert(well_formed_bootstrap),
#             # Create the pool token
#             InnerTxnBuilder.Begin(),
#             InnerTxnBuilder.SetFields(
#                 {
#                     TxnField.type_enum: TxnType.AssetConfig,
#                     TxnField.config_asset_name: Concat(
#                         Bytes("GovernanceToken-"), itoa(Global.current_application_id())
#                     ),
#                     TxnField.config_asset_unit_name: Bytes("algo-gov"),
#                     TxnField.config_asset_total: Int(total_supply),
#                     TxnField.config_asset_manager: me,
#                     TxnField.config_asset_reserve: me,
#                     TxnField.fee: Int(0),
#                 }
#             ),
#             InnerTxnBuilder.Submit(),
#             # Write it to global state
#             App.globalPut(pool_token_key, InnerTxn.created_asset_id()),
#             Int(1),
#         )
# 
