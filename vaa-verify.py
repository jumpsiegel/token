#!/usr/bin/python3
"""
================================================================================================

The VAA Signature Verify Stateless Program

(c) 2021 Randlabs, Inc.

Modified by Jump Crypto...

------------------------------------------------------------------------------------------------

This program verifies a subset of the signatures in a VAA against the guardian set. This
program works in tandem with the VAA Processor stateful program.

----

The difference between this version and the Randlabs version is we removed most of the asserts
since we are going to have to completely validate the arguments again in the
TokenBridge contract.  Lets keep this simple and flexible and just
have it do the signature verifications we ask it to.

We also cannot retroactively see/verify what arguments were passed into this
function unless all the arguments are in the Txn.application_args so
everything has to get moved out of the lsig args and into the txn_args

-----

================================================================================================

"""
from pyteal.ast import *
from pyteal.types import *
from pyteal.compiler import *
from pyteal.ir import *
from globals import *
from inlineasm import *

import sys

SLOTID_RECOVERED_PK_X = 240
SLOTID_RECOVERED_PK_Y = 241

@Subroutine(TealType.uint64)
def sig_check(signatures, digest, keys):
    si = ScratchVar(TealType.uint64)  # signature index (zero-based)
    ki = ScratchVar(TealType.uint64)  # key index
    slen = ScratchVar(TealType.uint64)  # signature length
    rec_pk_x = ScratchVar(TealType.bytes, SLOTID_RECOVERED_PK_X)
    rec_pk_y = ScratchVar(TealType.bytes, SLOTID_RECOVERED_PK_Y)

    return Seq(
        [
            rec_pk_x.store(Bytes("")),
            rec_pk_y.store(Bytes("")),
            slen.store(Len(signatures)),
            For(Seq([
                si.store(Int(0)),
                ki.store(Int(0))
            ]),
                si.load() < slen.load(),
                Seq([
                    si.store(si.load() + Int(66)),
                    ki.store(ki.load() + Int(20))
                ])).Do(
                    Seq([
                        InlineAssembly(
                            "ecdsa_pk_recover Secp256k1",
                            Keccak256(Keccak256(digest)),
                            Btoi(Extract(signatures, si.load() + Int(65), Int(1))),
                            Extract(signatures, si.load() + Int(1), Int(32)),       # R
                            Extract(signatures, si.load() + Int(33), Int(32)),      # S
                            type=TealType.none),

                        # returned values in stack, pass to scratch-vars

                        InlineAssembly("store " + str(SLOTID_RECOVERED_PK_Y)),
                        InlineAssembly("store " + str(SLOTID_RECOVERED_PK_X)),

                        # Generate Ethereum-type public key, compare with guardian key.

                        Assert(
                            Extract(keys, ki.load(), Int(20)) ==
                            Substring(Keccak256(Concat(rec_pk_x.load(),
                                    rec_pk_y.load())), Int(12), Int(32))
                        )
                    ])


            ),
            Return(Int(1))
        ]
    )

def vaa_verify_program():
    digest = Txn.note()
    signatures = Txn.application_args[1]
    keys = Txn.application_args[2]
    num_guardians = Txn.application_args[3]

    return Seq([
        Assert(Txn.application_args.length() == Int(4)),
        Assert(Txn.rekey_to() == Global.zero_address()),
        Assert(Txn.type_enum() == TxnType.ApplicationCall),
        Assert(sig_check(signatures, digest, keys)),
        Approve()]
    )
