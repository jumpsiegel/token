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
    teal = compileTeal(contract, mode=Mode.Application, version=6)
    response = client.compile(teal)
    return response

def clear_app():
    return Int(1)

def approve_app():
    me = Global.current_application_address()

    def nop():
        return Seq([Approve()])

    def setup():
        return Seq([
            InnerTxnBuilder.Begin(),
            InnerTxnBuilder.SetFields(
                {
                    TxnField.sender: me,
                    TxnField.type_enum: TxnType.AssetConfig,
                    TxnField.config_asset_name: Bytes("TestAsset"),
                    TxnField.config_asset_unit_name: Bytes("testAsse"),
                    TxnField.config_asset_total: Int(int(1e17)),
                    TxnField.config_asset_decimals: Int(16),
                    TxnField.config_asset_manager: me,
                    TxnField.config_asset_reserve: me,

                    # We cannot freeze or clawback assets... per the spirit of 
                    TxnField.config_asset_freeze: Global.zero_address(),
                    TxnField.config_asset_clawback: Global.zero_address(),

                    TxnField.fee: Int(0),
                }
            ),
            InnerTxnBuilder.Submit(),

            Log(Itob(InnerTxn.created_asset_id())),

            Approve()
        ])

    METHOD = Txn.application_args[0]

    router = Cond(
        [METHOD == Bytes("nop"), nop()],
        [METHOD == Bytes("setup"), setup()],
    )

    on_create = Seq( [
        Return(Int(1))
    ])

    on_update = Seq( [
        Return(Int(1))
    ] )

    on_delete = Seq( [
        Return(Int(1))
    ] )

    on_optin = Seq( [
        Return(Int(1))
    ] )

    return Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
        [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
        [Txn.on_completion() == OnComplete.OptIn, on_optin],
        [Txn.on_completion() == OnComplete.NoOp, router]
    )

def get_test_app(client: AlgodClient) -> Tuple[bytes, bytes]:
    APPROVAL_PROGRAM = fullyCompileContract(client, approve_app())
    CLEAR_STATE_PROGRAM = fullyCompileContract(client, clear_app())

    return APPROVAL_PROGRAM, CLEAR_STATE_PROGRAM
