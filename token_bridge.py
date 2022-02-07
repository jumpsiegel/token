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
