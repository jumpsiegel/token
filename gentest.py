from eth_abi import encode_single, encode_abi
import sys
import pprint
import time
from Cryptodome.Hash import keccak
import coincurve

class GenTest:
    def __init__(self) -> None:
        self.guardianKeys = [
            "52A26Ce40F8CAa8D36155d37ef0D5D783fc614d2",
            "389A74E8FFa224aeAD0778c786163a7A2150768C",
            "B4459EA6482D4aE574305B239B4f2264239e7599",
            "072491bd66F63356090C11Aae8114F5372aBf12B",
            "51280eA1fd2B0A1c76Ae29a7d54dda68860A2bfF",
            "fa9Aa60CfF05e20E2CcAA784eE89A0A16C2057CB",
            "e42d59F8FCd86a1c5c4bA351bD251A5c5B05DF6A",
            "4B07fF9D5cE1A6ed58b6e9e7d6974d1baBEc087e",
            "c8306B84235D7b0478c61783C50F990bfC44cFc0",
            "C8C1035110a13fe788259A4148F871b52bAbcb1B",
            "58A2508A20A7198E131503ce26bBE119aA8c62b2",
            "8390820f04ddA22AFe03be1c3bb10f4ba6CF94A0",
            "1FD6e97387C34a1F36DE0f8341E9D409E06ec45b",
            "255a41fC2792209CB998A8287204D40996df9E54",
            "bA663B12DD23fbF4FbAC618Be140727986B3BBd0",
            "79040E577aC50486d0F6930e160A5C75FD1203C6",
            "3580D2F00309A9A85efFAf02564Fc183C0183A96",
            "3869795913D3B6dBF3B24a1C7654672c69A23c35",
            "1c0Cc52D7673c52DE99785741344662F5b2308a0",
        ]

        self.guardianPrivKeys = [
            "563d8d2fd4e701901d3846dee7ae7a92c18f1975195264d676f8407ac5976757",
            "8d97f25916a755df1d9ef74eb4dbebc5f868cb07830527731e94478cdc2b9d5f",
            "9bd728ad7617c05c31382053b57658d4a8125684c0098f740a054d87ddc0e93b",
            "5a02c4cd110d20a83a7ce8d1a2b2ae5df252b4e5f6781c7855db5cc28ed2d1b4",
            "93d4e3b443bf11f99a00901222c032bd5f63cf73fc1bcfa40829824d121be9b2",
            "ea40e40c63c6ff155230da64a2c44fcd1f1c9e50cacb752c230f77771ce1d856",
            "87eaabe9c27a82198e618bca20f48f9679c0f239948dbd094005e262da33fe6a",
            "61ffed2bff38648a6d36d6ed560b741b1ca53d45391441124f27e1e48ca04770",
            "bd12a242c6da318fef8f98002efb98efbf434218a78730a197d981bebaee826e",
            "20d3597bb16525b6d09e5fb56feb91b053d961ab156f4807e37d980f50e71aff",
            "344b313ffbc0199ff6ca08cacdaf5dc1d85221e2f2dc156a84245bd49b981673",
            "848b93264edd3f1a521274ca4da4632989eb5303fd15b14e5ec6bcaa91172b05",
            "c6f2046c1e6c172497fc23bd362104e2f4460d0f61984938fa16ef43f27d93f6",
            "693b256b1ee6b6fb353ba23274280e7166ab3be8c23c203cc76d716ba4bc32bf",
            "13c41508c0da03018d61427910b9922345ced25e2bbce50652e939ee6e5ea56d",
            "460ee0ee403be7a4f1eb1c63dd1edaa815fbaa6cf0cf2344dcba4a8acf9aca74",
            "b25148579b99b18c8994b0b86e4dd586975a78fa6e7ad6ec89478d7fbafd2683",
            "90d7ac6a82166c908b8cf1b352f3c9340a8d1f2907d7146fb7cd6354a5436cca",
            "b71d23908e4cf5d6cd973394f3a4b6b164eb1065785feee612efdfd8d30005ed",
        ]

        self.zeroPadBytes = "00"*64

    def encoder(self, type, val):
        if type == 'uint8':
            return encode_single(type, val).hex()[62:64]
        if type == 'uint16':
            return encode_single(type, val).hex()[60:64]
        if type == 'uint32':
            return encode_single(type, val).hex()[56:64]
        if type == 'uint64':
            return encode_single(type, val).hex()[64-(16):64]
        if type == 'uint128':
            return encode_single(type, val).hex()[64-(32):64]
        if type == 'uint256' or type == 'bytes32':
            return encode_single(type, val).hex()[64-(64):64]
        raise Exception("you suck")

    def createSignedVAA(self, guardianSetIndex, signers, ts, nonce, emitterChainId, emitterAddress, sequence, consistencyLevel, target, payload):
        b = ""

        b += self.encoder("uint32", ts)
        b += self.encoder("uint32", nonce)
        b += self.encoder("uint16", emitterChainId)
        b += self.encoder("bytes32", emitterAddress)
        b += self.encoder("uint64", sequence)
        b += self.encoder("uint8", consistencyLevel)
        b += payload

        hash = keccak.new(digest_bits=256).update(keccak.new(digest_bits=256).update(bytes.fromhex(b)).digest()).digest()

        signatures = ""

        for  i in range(len(signers)):
            signatures += self.encoder("uint8", i)

            key = coincurve.PrivateKey(bytes.fromhex(signers[i]))
            signature = key.sign_recoverable(hash, hasher=None)
            signatures += signature.hex()

        ret  = self.encoder("uint8", 1)
        ret += self.encoder("uint32", guardianSetIndex)
        ret += self.encoder("uint8", len(signers))
        ret += signatures
        ret += b

        return ret

    def genGuardianSetUpgrade(self, signers, guardianSet, targetSet, nonce, seq):
        b  = self.zeroPadBytes[0:(28*2)]
        b += self.encoder("uint8", ord("C"))
        b += self.encoder("uint8", ord("o"))
        b += self.encoder("uint8", ord("r"))
        b += self.encoder("uint8", ord("e"))
        b += self.encoder("uint8", 2)
        b += self.encoder("uint16", 0)
        b += self.encoder("uint32", targetSet)
        b += self.encoder("uint8", len(self.guardianKeys))

        for i in self.guardianKeys:
            b += i

        emitter = bytes.fromhex(self.zeroPadBytes[0:(31*2)] + "04")
    
        return self.createSignedVAA(guardianSet, signers, int(time.time()), nonce, 1, emitter, seq, 0, 0, b)

    def test(self):
        print(self.genGuardianSetUpgrade(self.guardianPrivKeys, 1, 1, 1, 1))

if __name__ == '__main__':    
    core = GenTest()
    core.test()
