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

import sys

def fullyCompileContract(client: AlgodClient, contract: Expr) -> bytes:
    teal = compileTeal(contract, mode=Mode.Application, version=5)
    response = client.compile(teal)
    return response

def clear_token_bridge():
    return Int(1)

@Subroutine(TealType.bytes)
def extract_value(id) -> Expr:
    maybe = AssetParam.url(id)

    return Seq(maybe, Assert(maybe.hasValue()), maybe.value())

def attest():
    me = Global.current_application_address()

    return Seq([
        Assert(And(
            Gtxn[Txn.group_index() - Int(2)].type_enum() == TxnType.ApplicationCall,
            Gtxn[Txn.group_index() - Int(2)].application_id() == App.globalGet(Bytes("coreid")),
            Gtxn[Txn.group_index() - Int(2)].application_args[0] == Bytes("verifyVAA"),
            Gtxn[Txn.group_index() - Int(2)].sender() == Txn.sender(),
            Gtxn[Txn.group_index() - Int(2)].rekey_to() == Global.zero_address(),

            Gtxn[Txn.group_index() - Int(1)].type_enum() == TxnType.Payment,
            Gtxn[Txn.group_index() - Int(1)].amount() >= Int(200000),
#            Gtxn[Txn.group_index() - Int(1)].receiver() == Global.current_application_id(),
            Gtxn[Txn.group_index() - Int(1)].rekey_to() == Global.zero_address(),

            (Global.group_size() - Int(1)) == Txn.group_index()    # This should be the last entry...
        )),

        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields(
            {
                TxnField.type_enum: TxnType.AssetConfig,
                TxnField.config_asset_name: Bytes("hiMom"),
                TxnField.config_asset_unit_name: Bytes("algo-gov"),
                TxnField.config_asset_total: Int(int(1e17)),
                TxnField.config_asset_manager: me,
                TxnField.config_asset_freeze: me,
                TxnField.config_asset_clawback: me,
                TxnField.config_asset_reserve: me,
                TxnField.config_asset_url: Bytes("there"),
                TxnField.fee: Int(0),
            }
        ),
        InnerTxnBuilder.Submit(),
        # Write it to global state

        #Log(extract_value(InnerTxn.created_asset_id())),

        Approve()
    ])

def approve_token_bridge():
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

    on_optin = Seq( [
        Reject()
    ])

    return Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
        [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
        [Txn.on_completion() == OnComplete.OptIn, on_optin],
        [Txn.on_completion() == OnComplete.NoOp, router]
    )

def get_token_bridge(client: AlgodClient) -> Tuple[bytes, bytes]:
    APPROVAL_PROGRAM = fullyCompileContract(client, approve_token_bridge())
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
