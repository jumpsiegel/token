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

def approve_token_bridge():
    return Seq([
        Approve()]
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
