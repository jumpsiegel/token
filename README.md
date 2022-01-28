 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
 rustip default nightly-2021-08-01

[jsiegel@gusc1a-ossdev-jsl1 ~/.../wormhole/cli]{reisen/cli} BRIDGE_ADDRESS="" EMITTER_ADDRESS="" cargo build
[jsiegel@gusc1a-ossdev-jsl1 ~/.../target/debug](reisen/cli) ./wormhole vaa dump ....

node gentest.js

            const signedVAA = hexStringToByteArray("0100000000010017fa5858d0e1c87641f5e0f477fd2dec17e1ae8db0c523e196ce87af21810f571315354a17c24c282808a3e72c8f1223b3cce9a35f41ff84d41f0f3e92d384f70061d74a200000e6d20001c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f00000000000000472002165809739240a0ac03b98440fe8985548e3aa683cd0d4d9df5b5659669faa301000109534f4c5400000000000000000000000000000000000000000000000000000000536f6c616e61205465737420546f6b656e000000000000000000000000000000")

# token

The problem:

1. a trusted player deploys master contract (wormhole foundation)

2. untrusted players funds/call "createWrapped" with a on that master contract to create new assets

   The master contract verifies the legitimacy of the payload first
   by looking at signatures from predefined guardians who signed
   it. That verification is outside the scope of this example

3. untrusted player calls "redemeWrapped" with a on the master contract to mint from that newly created asset

   Not only do we need to validate the redeme call, we need to do
   duplicate suppression to prevent redeming twice...

source
<smartContract> <EmitterChain> -> <algo asset> <smartContract> <EmitterChain>
<EmitterSource> <SequenceNumber> -> <Bit> (duplicate suppresion)

<GovernanceIndex (int)> -> <algo app> 19 publicKeys for VAA signers <32\*19>

==

./wormhole vaa dump 010000000001000a68545d22fd7cd9381923681b2acb58c6c6de295f2f5bd4c38302a18252f9210a7bc8666b4d3bed5014bc1ae4a78359a74d789b6c6cb75c21fd9c3af1b063c4000000000100000001000100000000000000000000000000000000000000000000000000000000000000040000000004fe59d900000000000000000000000000000000000000000000546f6b656e4272696467650100000001842ba2b26475774f1d83796fa0963e873c51545bd499ebfb1ee116d6ad4fb913

Dumping VAA, 192 Bytes

 0000: Version      | 01                              
 0001: Index        | 00000000                        
 0005: Siglen       | 01                              
 0006: Sig 0        | 000a6854 5d22fd7c d9381923 681b2acb 58c6c6de 295f2f5b d4c38302 a18252f9 210a7bc8 666b4d3b ed5014bc 1ae4a783 59a74d78 9b6c6cb7 5c21fd9c 3af1b063 c400
 0072: Timestamp    | 00000001                        
 0076: Nonce        | 00000001                        
 0080: Chain        | 0001                            
 0082: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 0114: Sequence     | 00000000 04fe59d9               
 0122: Consistency  | 00                              

Signers (1):

 0000 | 0x13947b... | Unknown Guardian

Dumping Digest, 120 Bytes

 0000: Timestamp    | 00000001                        
 0004: Nonce        | 00000001                        
 0008: Chain        | 0001                            
 0010: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 0042: Sequence     | 00000000 04fe59d9               
 0050: Consistency  | 00                              
 0051: Payload      | 00000000 00000000 00000000 00000000 00000000 00546f6b 656e4272 69646765
 0083: Payload      | 01000000 01842ba2 b2647577 4f1d8379 6fa0963e 873c5154 5bd499eb fb1ee116
 0115: Payload      | d6ad4fb9 13                     

Dumping Payload: TokenBridge RegisterChain, 69 Bytes

 0000: Module       | 00000000 00000000 00000000 00000000 00000000 00546f6b 656e4272 69646765
 0032: Type         | 01                              
 0033: Chain        | 0000                            
 0035: Endpoint     | 0001842b a2b26475 774f1d83 796fa096 3e873c51 545bd499 ebfb1ee1 16d6ad4f



++ ./wormhole vaa dump 01000000011300cf201e6dcdb82cb2a6be80968c9ee262aa836e43a49ac74c4cdf12223c6f79101f17d9b56d5675508b487354f7a74cf621fefbb7baed19ef28b80d8139ed8ba300014fcfb795678f8aadbcdb0dd26760529b43ed4504ff546c1af46345892ac5f1662884b181ee1a8cd464045fb1f88d6be30157222f40938096393593bd9d207cef01027adfe2602b4f6fdc21798d57c42c2c5b0176543d2d75001c5ba97572653c2165207e1e9219b2d0cdca63aaf3b14fb42ec822b3b85a94cd23b4cc8f5fd4cf12ae0103e47185229ce099c80e8231f1527999696c6244c31e11653db3cf66c033fbe2771ecb69068fc79c21ceb663557ba2cb415c9298e51942e7f3add225f4cea1ec6201041c6f900ea522fdb9520c65df8aff3619bc6f846178e07b84d845b4ad818b2e49003f25a69c436ba23bb3d5cd21c7642e3c1f27197b7325fbc740797d1f25fcd10005c5af04197dd499889e5abeb83b57cf28989e024f06fe8133b8bf7f290cf8c69a3261e8cedc7dd9bdaf494c4ece98e8696a57281ef8d401fa4e813e2a8297ec36000657824bd37ea4da8cb41c79c0a063346a742942e4057509088ea8f22c667b688829660747d401e340595f4c093e17debd4cd25a4565d9533d815739790115bd4c0007380588f30e7bc4539fd7a435887d66d04508393d7ada81e48d215a089af87f994a28606d98a797669962ec4970996f67ed6d165e7f4efb6fc9b31f30a304954600088c64c8c8cc6dd4adf09b111818d364306cd25f929d93478ed1398d7208d87b2021fa94e104980ca0b88e4050aa8f1564c8dac444fb6ad3d52da4ed34c471a1a30009d5a24dd8697b96529558b0dc395bc14eccadbda48addaf61f7bdc7a5a3166180468d7e9ee50ddd6b7eae4a1590e1c7dfc24712cb0ad1952c2957ce35b27561ec000a83435356db4f78188b3fbc18df941ff1660e73130cf1ce138d16b700be738c797a03878e42fbba178a562b96f13334d1c601144f6241bfec09fcaf4d935dbb05010b93a6d74a3ffba86f1e467899b3321598db99b0bc7c1e00a9af1a6822a9493a5b5d8ab1c3fe0dda8b695c5d982aa5e0f394b68086e413b302da65d4cc21ff5894000cace9bc97d30ce2d289bcdc6dcf73065eaba63f52546fe34ffcf4c48bd884aef134d4fb2d495d4cdd24dfe4b8195bcdbbacbdb6498ba4c681dc62aab5f5f11c06000d62ea688c37b032ed3fd9da115184bc1f22ae061bd9f44eb522785132101a05ee66131259d0fa208b2e880c03875b5d855662c0849c9dc30316845bca252f1b3d000e0288c2606c2186dd4c7946cf7963588f042faea22a6458d34eed615a7052e6e063a32f0c0d445ec78c6bc888697097a8b1952e54609f8976afcb102bdaa3dbc1000fff79a979a2044d3f316bdb8f4e1bd57bae9e9bfd759944a1017a8efb952a10032286d80ec570d2ad03cc1241fd0cf4f81493a851e8d6c419176429a3a7f2c372011041f67d6848c634366536dae41f1852b8618980d2691c7dc7a17050ea3e6af2a51bec7ea237b230d79cfb155564f7e3b43db1e64c3d63a8e916dda5b0465e2c48001139c7f780f7605d4c13125391ee763903235b949341fbf311b82c4128ead9dcdf3d57c4978a82c5230372698c99811db71f1573cbb310e734e54ed533a59dccd101124058834db97c784943183118b1cbb58fd722ff44f8a941e36a5d26a478730e6916c54e5a1f42809744bf9ff1d945d0ce3b93cc64b0d0b6a5f97cea4401e2ee430161f3caf3000000010001000000000000000000000000000000000000000000000000000000000000000400000000000000010000000000000000000000000000000000000000000000000000000000436f7265020000000000011352A26Ce40F8CAa8D36155d37ef0D5D783fc614d2389A74E8FFa224aeAD0778c786163a7A2150768CB4459EA6482D4aE574305B239B4f2264239e7599072491bd66F63356090C11Aae8114F5372aBf12B51280eA1fd2B0A1c76Ae29a7d54dda68860A2bfFfa9Aa60CfF05e20E2CcAA784eE89A0A16C2057CBe42d59F8FCd86a1c5c4bA351bD251A5c5B05DF6A4B07fF9D5cE1A6ed58b6e9e7d6974d1baBEc087ec8306B84235D7b0478c61783C50F990bfC44cFc0C8C1035110a13fe788259A4148F871b52bAbcb1B58A2508A20A7198E131503ce26bBE119aA8c62b28390820f04ddA22AFe03be1c3bb10f4ba6CF94A01FD6e97387C34a1F36DE0f8341E9D409E06ec45b255a41fC2792209CB998A8287204D40996df9E54bA663B12DD23fbF4FbAC618Be140727986B3BBd079040E577aC50486d0F6930e160A5C75FD1203C63580D2F00309A9A85efFAf02564Fc183C0183A963869795913D3B6dBF3B24a1C7654672c69A23c351c0Cc52D7673c52DE99785741344662F5b2308a0

Dumping VAA, 1731 Bytes

 0000: Version      | 01                              
 0001: Index        | 00000001                        
 0005: Siglen       | 13                              
 0006: Sig 0        | 00cf201e 6dcdb82c b2a6be80 968c9ee2 62aa836e 43a49ac7 4c4cdf12 223c6f79 101f17d9 b56d5675 508b4873 54f7a74c f621fefb b7baed19 ef28b80d 8139ed8b a300
 0072: Sig 1        | 014fcfb7 95678f8a adbcdb0d d2676052 9b43ed45 04ff546c 1af46345 892ac5f1 662884b1 81ee1a8c d464045f b1f88d6b e3015722 2f409380 96393593 bd9d207c ef01
 0138: Sig 2        | 027adfe2 602b4f6f dc21798d 57c42c2c 5b017654 3d2d7500 1c5ba975 72653c21 65207e1e 9219b2d0 cdca63aa f3b14fb4 2ec822b3 b85a94cd 23b4cc8f 5fd4cf12 ae01
 0204: Sig 3        | 03e47185 229ce099 c80e8231 f1527999 696c6244 c31e1165 3db3cf66 c033fbe2 771ecb69 068fc79c 21ceb663 557ba2cb 415c9298 e51942e7 f3add225 f4cea1ec 6201
 0270: Sig 4        | 041c6f90 0ea522fd b9520c65 df8aff36 19bc6f84 6178e07b 84d845b4 ad818b2e 49003f25 a69c436b a23bb3d5 cd21c764 2e3c1f27 197b7325 fbc74079 7d1f25fc d100
 0336: Sig 5        | 05c5af04 197dd499 889e5abe b83b57cf 28989e02 4f06fe81 33b8bf7f 290cf8c6 9a3261e8 cedc7dd9 bdaf494c 4ece98e8 696a5728 1ef8d401 fa4e813e 2a8297ec 3600
 0402: Sig 6        | 0657824b d37ea4da 8cb41c79 c0a06334 6a742942 e4057509 088ea8f2 2c667b68 88296607 47d401e3 40595f4c 093e17de bd4cd25a 4565d953 3d815739 790115bd 4c00
 0468: Sig 7        | 07380588 f30e7bc4 539fd7a4 35887d66 d0450839 3d7ada81 e48d215a 089af87f 994a2860 6d98a797 669962ec 4970996f 67ed6d16 5e7f4efb 6fc9b31f 30a30495 4600
 0534: Sig 8        | 088c64c8 c8cc6dd4 adf09b11 1818d364 306cd25f 929d9347 8ed1398d 7208d87b 2021fa94 e104980c a0b88e40 50aa8f15 64c8dac4 44fb6ad3 d52da4ed 34c471a1 a300
 0600: Sig 9        | 09d5a24d d8697b96 529558b0 dc395bc1 4eccadbd a48addaf 61f7bdc7 a5a31661 80468d7e 9ee50ddd 6b7eae4a 1590e1c7 dfc24712 cb0ad195 2c2957ce 35b27561 ec00
 0666: Sig 10       | 0a834353 56db4f78 188b3fbc 18df941f f1660e73 130cf1ce 138d16b7 00be738c 797a0387 8e42fbba 178a562b 96f13334 d1c60114 4f6241bf ec09fcaf 4d935dbb 0501
 0732: Sig 11       | 0b93a6d7 4a3ffba8 6f1e4678 99b33215 98db99b0 bc7c1e00 a9af1a68 22a9493a 5b5d8ab1 c3fe0dda 8b695c5d 982aa5e0 f394b680 86e413b3 02da65d4 cc21ff58 9400
 0798: Sig 12       | 0cace9bc 97d30ce2 d289bcdc 6dcf7306 5eaba63f 52546fe3 4ffcf4c4 8bd884ae f134d4fb 2d495d4c dd24dfe4 b8195bcd bbacbdb6 498ba4c6 81dc62aa b5f5f11c 0600
 0864: Sig 13       | 0d62ea68 8c37b032 ed3fd9da 115184bc 1f22ae06 1bd9f44e b5227851 32101a05 ee661312 59d0fa20 8b2e880c 03875b5d 855662c0 849c9dc3 0316845b ca252f1b 3d00
 0930: Sig 14       | 0e0288c2 606c2186 dd4c7946 cf796358 8f042fae a22a6458 d34eed61 5a7052e6 e063a32f 0c0d445e c78c6bc8 88697097 a8b1952e 54609f89 76afcb10 2bdaa3db c100
 0996: Sig 15       | 0fff79a9 79a2044d 3f316bdb 8f4e1bd5 7bae9e9b fd759944 a1017a8e fb952a10 032286d8 0ec570d2 ad03cc12 41fd0cf4 f81493a8 51e8d6c4 19176429 a3a7f2c3 7201
 1062: Sig 16       | 1041f67d 6848c634 366536da e41f1852 b8618980 d2691c7d c7a17050 ea3e6af2 a51bec7e a237b230 d79cfb15 5564f7e3 b43db1e6 4c3d63a8 e916dda5 b0465e2c 4800
 1128: Sig 17       | 1139c7f7 80f7605d 4c131253 91ee7639 03235b94 9341fbf3 11b82c41 28ead9dc df3d57c4 978a82c5 23037269 8c99811d b71f1573 cbb310e7 34e54ed5 33a59dcc d101
 1194: Sig 18       | 12405883 4db97c78 49431831 18b1cbb5 8fd722ff 44f8a941 e36a5d26 a478730e 6916c54e 5a1f4280 9744bf9f f1d945d0 ce3b93cc 64b0d0b6 a5f97cea 4401e2ee 4301
 1260: Timestamp    | 61f3caf3                        
 1264: Nonce        | 00000001                        
 1268: Chain        | 0001                            
 1270: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 1302: Sequence     | 00000000 00000001               
 1310: Consistency  | 00                              

Signers (19):

 0000 | 0x52a26c... | Unknown Guardian
 0001 | 0x389a74... | Unknown Guardian
 0002 | 0xb4459e... | Unknown Guardian
 0003 | 0x072491... | Unknown Guardian
 0004 | 0x51280e... | Unknown Guardian
 0005 | 0xfa9aa6... | Unknown Guardian
 0006 | 0xe42d59... | Unknown Guardian
 0007 | 0x4b07ff... | Unknown Guardian
 0008 | 0xc8306b... | Unknown Guardian
 0009 | 0xc8c103... | Unknown Guardian
 0010 | 0x58a250... | Unknown Guardian
 0011 | 0x839082... | Unknown Guardian
 0012 | 0x1fd6e9... | Unknown Guardian
 0013 | 0x255a41... | Unknown Guardian
 0014 | 0xba663b... | Unknown Guardian
 0015 | 0x79040e... | Unknown Guardian
 0016 | 0x3580d2... | Unknown Guardian
 0017 | 0x386979... | Unknown Guardian
 0018 | 0x1c0cc5... | Unknown Guardian

Dumping Digest, 471 Bytes

 0000: Timestamp    | 61f3caf3                        
 0004: Nonce        | 00000001                        
 0008: Chain        | 0001                            
 0010: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 0042: Sequence     | 00000000 00000001               
 0050: Consistency  | 00                              
 0051: Payload      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 436f7265
 0083: Payload      | 02000000 00000113 52a26ce4 0f8caa8d 36155d37 ef0d5d78 3fc614d2 389a74e8
 0115: Payload      | ffa224ae ad0778c7 86163a7a 2150768c b4459ea6 482d4ae5 74305b23 9b4f2264
 0147: Payload      | 239e7599 072491bd 66f63356 090c11aa e8114f53 72abf12b 51280ea1 fd2b0a1c
 0179: Payload      | 76ae29a7 d54dda68 860a2bff fa9aa60c ff05e20e 2ccaa784 ee89a0a1 6c2057cb
 0211: Payload      | e42d59f8 fcd86a1c 5c4ba351 bd251a5c 5b05df6a 4b07ff9d 5ce1a6ed 58b6e9e7
 0243: Payload      | d6974d1b abec087e c8306b84 235d7b04 78c61783 c50f990b fc44cfc0 c8c10351
 0275: Payload      | 10a13fe7 88259a41 48f871b5 2babcb1b 58a2508a 20a7198e 131503ce 26bbe119
 0307: Payload      | aa8c62b2 8390820f 04dda22a fe03be1c 3bb10f4b a6cf94a0 1fd6e973 87c34a1f
 0339: Payload      | 36de0f83 41e9d409 e06ec45b 255a41fc 2792209c b998a828 7204d409 96df9e54
 0371: Payload      | ba663b12 dd23fbf4 fbac618b e1407279 86b3bbd0 79040e57 7ac50486 d0f6930e
 0403: Payload      | 160a5c75 fd1203c6 3580d2f0 0309a9a8 5effaf02 564fc183 c0183a96 38697959
 0435: Payload      | 13d3b6db f3b24a1c 7654672c 69a23c35 1c0cc52d 7673c52d e9978574 1344662f
 0467: Payload      | 5b2308a0                        

Dumping Payload: Core GuardianSetChange, 420 Bytes

 0000: Module       | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 436f7265
 0032: Action       | 02                              
 0033: Chain        | 0000                            
 0035: NewGuardianSetIndex | 00000001                        
 0039: NewGuardianSetLen | 13                              
 0040: key          | 52a26ce4 0f8caa8d 36155d37 ef0d5d78 3fc614d2
 0060: key          | 389a74e8 ffa224ae ad0778c7 86163a7a 2150768c
 0080: key          | b4459ea6 482d4ae5 74305b23 9b4f2264 239e7599
 0100: key          | 072491bd 66f63356 090c11aa e8114f53 72abf12b
 0120: key          | 51280ea1 fd2b0a1c 76ae29a7 d54dda68 860a2bff
 0140: key          | fa9aa60c ff05e20e 2ccaa784 ee89a0a1 6c2057cb
 0160: key          | e42d59f8 fcd86a1c 5c4ba351 bd251a5c 5b05df6a
 0180: key          | 4b07ff9d 5ce1a6ed 58b6e9e7 d6974d1b abec087e
 0200: key          | c8306b84 235d7b04 78c61783 c50f990b fc44cfc0
 0220: key          | c8c10351 10a13fe7 88259a41 48f871b5 2babcb1b
 0240: key          | 58a2508a 20a7198e 131503ce 26bbe119 aa8c62b2
 0260: key          | 8390820f 04dda22a fe03be1c 3bb10f4b a6cf94a0
 0280: key          | 1fd6e973 87c34a1f 36de0f83 41e9d409 e06ec45b
 0300: key          | 255a41fc 2792209c b998a828 7204d409 96df9e54
 0320: key          | ba663b12 dd23fbf4 fbac618b e1407279 86b3bbd0
 0340: key          | 79040e57 7ac50486 d0f6930e 160a5c75 fd1203c6
 0360: key          | 3580d2f0 0309a9a8 5effaf02 564fc183 c0183a96
 0380: key          | 38697959 13d3b6db f3b24a1c 7654672c 69a23c35
 0400: key          | 1c0cc52d 7673c52d e9978574 1344662f 5b2308a0

++ ./wormhole vaa dump 01000000011300e7e412681be729892ffe76678409efcfebc4531ce43a953e9d4d01dea58a8dd9367f2ea9019052815bb9b67140752e1cb14a9d6925fef70ec596a993fbbcd5fe0001f31e5a87ee135c69188f3a06584148b0844f87255d7ad877a575a740fd832d3f2a0e83bb40f8a1076e810d5f3c34f66df9ed7c96f46cc2cc71709381d0ca82e40002df2f80d550e86fdf2453c075ad04a579a57acdedd88593784f6e97268d9ffeb2477ab18de1e2a9b972b4c36efda444dc25e91874d56da5a18a002eddd03575e200036acc41cec22f08b2d49e2779fe5135ce02db0bd1cb167f8a84193a7cc1549adc1b0bf6334046573a0598f1e6bcfdc19b9951c9ffbb57b2140c4c7276b5f6773701043c05854197eb700e8a4b2affd2ba2aa369b599d06600b434c01c7b71d5dab5f03b5d18c09f03900182812e26e8e4e6a6b9647b1fe65cde5ed55f0de9263f12760005dbcb151ab9a5123609b391f5b3112fda69e5fcb2f0adf446f1a07156f242fae46bd395933dfa859bedeab0c5fcf1706d736de634c210808a431d52096c652ff90106b2d61997362ec61359dce06f83db2c33a0ad6d67b91bce53afde6b1c3dcd88d76d7ab786dbf7eeb664eb9f851941dad8404c85943d0cbcc4804bdcc2d262490c01070b40c60f10a236e14c0094376759bf1ab677cc822408a9cae21fba0f889e58e0029164579a97439524c0ed9354725153255e8322167837bc27eb970e9087f21800089df311b342c76e398eefd9e1e28569f5fff9f12e1e11e8cf2d0c7fca3082b366427b59a254acae33ebfece0506a8b85f1ead9fd9df4fa1e69fdddf435c795c53000941375cde90aa65062b48e2f705466ffae643fb63849182507cb7ae9a153863440c052367026f3df1d3ed68ddfd364710e6304714dfc53d2ae1d6eab6b279fae6010afc1109dcadf17814617f57513a911ac66fae4c32775642da0bd9d41819e7b17023db9541f8aeca6d55be41c8eda2d3a552d1361f6c5cf43ced96de2472c4da4a010b4f42898e6c0209b90518bff977a1ddec3dd310b1107cedd48a933aa27c224bba4caeb83f074cd1d2b8700b9ef4419917a4edc0548021716980981aafb9db9913010c2a6a83d4f4c32f41466d447a8a347ee471e28070d464e476cd5c8ff6bd116ec96817017c86bd6fa92e5d1b1a3ea7ce981ad0deab21268e7f611fca144a5534fd010d8fd4e409c9d41f765425fe6d31f3f63467625910b6fe9307703363c77d30f4aa2ef459ddcab286662558281bb055aca5d1e7a4a60c1cc2c564d699941cd23cb9010ef22de56480e3488f2102774faabe6d3a7e9453aab4b9a20c438d5a9371ad8c65330579136333f9a083f5cb6fcbbc79b8499e48c439f09212d8fb9e369430e030010fdec4e356ecac0013e86fcd720d6db5e34adbe322a6d36f14d3556f04a7d6040176d61adcab433507d8073c75b5785bae425208603b0392b2ab1a83d0e2d08e20011030a5c58be979b410cab6b2041d33fd851caed666b7614313d82dbc83ec33beee508d55b8d7b44706efd22c6460f6eb250061988abc27a0979f3482df5ef7b6530111ceb4e68ab844a539c721cbef132b5dfc32ab7ba12ddf41b78005b6b2ce63a21167c015a454ae3553f2fbc064faa65bc5169842d0e1fae337d229aef2f126b18b0012576b6ac5662b7bf282e464bef9d81e16e0fc09ec09e5a4a41f061e48796019185e144f1e4c8d551b2d8618345bd4f8f318c7dea117e2946985325107ffe659ca0161f3caf3000000020001000000000000000000000000000000000000000000000000000000000000000400000000000000020000000000000000000000000000000000000000000000000000000000436f7265020000000000021352A26Ce40F8CAa8D36155d37ef0D5D783fc614d2389A74E8FFa224aeAD0778c786163a7A2150768CB4459EA6482D4aE574305B239B4f2264239e7599072491bd66F63356090C11Aae8114F5372aBf12B51280eA1fd2B0A1c76Ae29a7d54dda68860A2bfFfa9Aa60CfF05e20E2CcAA784eE89A0A16C2057CBe42d59F8FCd86a1c5c4bA351bD251A5c5B05DF6A4B07fF9D5cE1A6ed58b6e9e7d6974d1baBEc087ec8306B84235D7b0478c61783C50F990bfC44cFc0C8C1035110a13fe788259A4148F871b52bAbcb1B58A2508A20A7198E131503ce26bBE119aA8c62b28390820f04ddA22AFe03be1c3bb10f4ba6CF94A01FD6e97387C34a1F36DE0f8341E9D409E06ec45b255a41fC2792209CB998A8287204D40996df9E54bA663B12DD23fbF4FbAC618Be140727986B3BBd079040E577aC50486d0F6930e160A5C75FD1203C63580D2F00309A9A85efFAf02564Fc183C0183A963869795913D3B6dBF3B24a1C7654672c69A23c351c0Cc52D7673c52DE99785741344662F5b2308a0

Dumping VAA, 1731 Bytes

 0000: Version      | 01                              
 0001: Index        | 00000001                        
 0005: Siglen       | 13                              
 0006: Sig 0        | 00e7e412 681be729 892ffe76 678409ef cfebc453 1ce43a95 3e9d4d01 dea58a8d d9367f2e a9019052 815bb9b6 7140752e 1cb14a9d 6925fef7 0ec596a9 93fbbcd5 fe00
 0072: Sig 1        | 01f31e5a 87ee135c 69188f3a 06584148 b0844f87 255d7ad8 77a575a7 40fd832d 3f2a0e83 bb40f8a1 076e810d 5f3c34f6 6df9ed7c 96f46cc2 cc717093 81d0ca82 e400
 0138: Sig 2        | 02df2f80 d550e86f df2453c0 75ad04a5 79a57acd edd88593 784f6e97 268d9ffe b2477ab1 8de1e2a9 b972b4c3 6efda444 dc25e918 74d56da5 a18a002e ddd03575 e200
 0204: Sig 3        | 036acc41 cec22f08 b2d49e27 79fe5135 ce02db0b d1cb167f 8a84193a 7cc1549a dc1b0bf6 33404657 3a0598f1 e6bcfdc1 9b9951c9 ffbb57b2 140c4c72 76b5f677 3701
 0270: Sig 4        | 043c0585 4197eb70 0e8a4b2a ffd2ba2a a369b599 d06600b4 34c01c7b 71d5dab5 f03b5d18 c09f0390 0182812e 26e8e4e6 a6b9647b 1fe65cde 5ed55f0d e9263f12 7600
 0336: Sig 5        | 05dbcb15 1ab9a512 3609b391 f5b3112f da69e5fc b2f0adf4 46f1a071 56f242fa e46bd395 933dfa85 9bedeab0 c5fcf170 6d736de6 34c21080 8a431d52 096c652f f901
 0402: Sig 6        | 06b2d619 97362ec6 1359dce0 6f83db2c 33a0ad6d 67b91bce 53afde6b 1c3dcd88 d76d7ab7 86dbf7ee b664eb9f 851941da d8404c85 943d0cbc c4804bdc c2d26249 0c01
 0468: Sig 7        | 070b40c6 0f10a236 e14c0094 376759bf 1ab677cc 822408a9 cae21fba 0f889e58 e0029164 579a9743 9524c0ed 93547251 53255e83 22167837 bc27eb97 0e9087f2 1800
 0534: Sig 8        | 089df311 b342c76e 398eefd9 e1e28569 f5fff9f1 2e1e11e8 cf2d0c7f ca3082b3 66427b59 a254acae 33ebfece 0506a8b8 5f1ead9f d9df4fa1 e69fdddf 435c795c 5300
 0600: Sig 9        | 0941375c de90aa65 062b48e2 f705466f fae643fb 63849182 507cb7ae 9a153863 440c0523 67026f3d f1d3ed68 ddfd3647 10e63047 14dfc53d 2ae1d6ea b6b279fa e601
 0666: Sig 10       | 0afc1109 dcadf178 14617f57 513a911a c66fae4c 32775642 da0bd9d4 1819e7b1 7023db95 41f8aeca 6d55be41 c8eda2d3 a552d136 1f6c5cf4 3ced96de 2472c4da 4a01
 0732: Sig 11       | 0b4f4289 8e6c0209 b90518bf f977a1dd ec3dd310 b1107ced d48a933a a27c224b ba4caeb8 3f074cd1 d2b8700b 9ef44199 17a4edc0 54802171 6980981a afb9db99 1301
 0798: Sig 12       | 0c2a6a83 d4f4c32f 41466d44 7a8a347e e471e280 70d464e4 76cd5c8f f6bd116e c9681701 7c86bd6f a92e5d1b 1a3ea7ce 981ad0de ab21268e 7f611fca 144a5534 fd01
 0864: Sig 13       | 0d8fd4e4 09c9d41f 765425fe 6d31f3f6 34676259 10b6fe93 07703363 c77d30f4 aa2ef459 ddcab286 66255828 1bb055ac a5d1e7a4 a60c1cc2 c564d699 941cd23c b901
 0930: Sig 14       | 0ef22de5 6480e348 8f210277 4faabe6d 3a7e9453 aab4b9a2 0c438d5a 9371ad8c 65330579 136333f9 a083f5cb 6fcbbc79 b8499e48 c439f092 12d8fb9e 369430e0 3001
 0996: Sig 15       | 0fdec4e3 56ecac00 13e86fcd 720d6db5 e34adbe3 22a6d36f 14d3556f 04a7d604 0176d61a dcab4335 07d8073c 75b5785b ae425208 603b0392 b2ab1a83 d0e2d08e 2001
 1062: Sig 16       | 1030a5c5 8be979b4 10cab6b2 041d33fd 851caed6 66b76143 13d82dbc 83ec33be ee508d55 b8d7b447 06efd22c 6460f6eb 25006198 8abc27a0 979f3482 df5ef7b6 5301
 1128: Sig 17       | 11ceb4e6 8ab844a5 39c721cb ef132b5d fc32ab7b a12ddf41 b78005b6 b2ce63a2 1167c015 a454ae35 53f2fbc0 64faa65b c5169842 d0e1fae3 37d229ae f2f126b1 8b00
 1194: Sig 18       | 12576b6a c5662b7b f282e464 bef9d81e 16e0fc09 ec09e5a4 a41f061e 48796019 185e144f 1e4c8d55 1b2d8618 345bd4f8 f318c7de a117e294 69853251 07ffe659 ca01
 1260: Timestamp    | 61f3caf3                        
 1264: Nonce        | 00000002                        
 1268: Chain        | 0001                            
 1270: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 1302: Sequence     | 00000000 00000002               
 1310: Consistency  | 00                              

Signers (19):

 0000 | 0x52a26c... | Unknown Guardian
 0001 | 0x389a74... | Unknown Guardian
 0002 | 0xb4459e... | Unknown Guardian
 0003 | 0x072491... | Unknown Guardian
 0004 | 0x51280e... | Unknown Guardian
 0005 | 0xfa9aa6... | Unknown Guardian
 0006 | 0xe42d59... | Unknown Guardian
 0007 | 0x4b07ff... | Unknown Guardian
 0008 | 0xc8306b... | Unknown Guardian
 0009 | 0xc8c103... | Unknown Guardian
 0010 | 0x58a250... | Unknown Guardian
 0011 | 0x839082... | Unknown Guardian
 0012 | 0x1fd6e9... | Unknown Guardian
 0013 | 0x255a41... | Unknown Guardian
 0014 | 0xba663b... | Unknown Guardian
 0015 | 0x79040e... | Unknown Guardian
 0016 | 0x3580d2... | Unknown Guardian
 0017 | 0x386979... | Unknown Guardian
 0018 | 0x1c0cc5... | Unknown Guardian

Dumping Digest, 471 Bytes

 0000: Timestamp    | 61f3caf3                        
 0004: Nonce        | 00000002                        
 0008: Chain        | 0001                            
 0010: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 0042: Sequence     | 00000000 00000002               
 0050: Consistency  | 00                              
 0051: Payload      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 436f7265
 0083: Payload      | 02000000 00000213 52a26ce4 0f8caa8d 36155d37 ef0d5d78 3fc614d2 389a74e8
 0115: Payload      | ffa224ae ad0778c7 86163a7a 2150768c b4459ea6 482d4ae5 74305b23 9b4f2264
 0147: Payload      | 239e7599 072491bd 66f63356 090c11aa e8114f53 72abf12b 51280ea1 fd2b0a1c
 0179: Payload      | 76ae29a7 d54dda68 860a2bff fa9aa60c ff05e20e 2ccaa784 ee89a0a1 6c2057cb
 0211: Payload      | e42d59f8 fcd86a1c 5c4ba351 bd251a5c 5b05df6a 4b07ff9d 5ce1a6ed 58b6e9e7
 0243: Payload      | d6974d1b abec087e c8306b84 235d7b04 78c61783 c50f990b fc44cfc0 c8c10351
 0275: Payload      | 10a13fe7 88259a41 48f871b5 2babcb1b 58a2508a 20a7198e 131503ce 26bbe119
 0307: Payload      | aa8c62b2 8390820f 04dda22a fe03be1c 3bb10f4b a6cf94a0 1fd6e973 87c34a1f
 0339: Payload      | 36de0f83 41e9d409 e06ec45b 255a41fc 2792209c b998a828 7204d409 96df9e54
 0371: Payload      | ba663b12 dd23fbf4 fbac618b e1407279 86b3bbd0 79040e57 7ac50486 d0f6930e
 0403: Payload      | 160a5c75 fd1203c6 3580d2f0 0309a9a8 5effaf02 564fc183 c0183a96 38697959
 0435: Payload      | 13d3b6db f3b24a1c 7654672c 69a23c35 1c0cc52d 7673c52d e9978574 1344662f
 0467: Payload      | 5b2308a0                        

Dumping Payload: Core GuardianSetChange, 420 Bytes

 0000: Module       | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 436f7265
 0032: Action       | 02                              
 0033: Chain        | 0000                            
 0035: NewGuardianSetIndex | 00000002                        
 0039: NewGuardianSetLen | 13                              
 0040: key          | 52a26ce4 0f8caa8d 36155d37 ef0d5d78 3fc614d2
 0060: key          | 389a74e8 ffa224ae ad0778c7 86163a7a 2150768c
 0080: key          | b4459ea6 482d4ae5 74305b23 9b4f2264 239e7599
 0100: key          | 072491bd 66f63356 090c11aa e8114f53 72abf12b
 0120: key          | 51280ea1 fd2b0a1c 76ae29a7 d54dda68 860a2bff
 0140: key          | fa9aa60c ff05e20e 2ccaa784 ee89a0a1 6c2057cb
 0160: key          | e42d59f8 fcd86a1c 5c4ba351 bd251a5c 5b05df6a
 0180: key          | 4b07ff9d 5ce1a6ed 58b6e9e7 d6974d1b abec087e
 0200: key          | c8306b84 235d7b04 78c61783 c50f990b fc44cfc0
 0220: key          | c8c10351 10a13fe7 88259a41 48f871b5 2babcb1b
 0240: key          | 58a2508a 20a7198e 131503ce 26bbe119 aa8c62b2
 0260: key          | 8390820f 04dda22a fe03be1c 3bb10f4b a6cf94a0
 0280: key          | 1fd6e973 87c34a1f 36de0f83 41e9d409 e06ec45b
 0300: key          | 255a41fc 2792209c b998a828 7204d409 96df9e54
 0320: key          | ba663b12 dd23fbf4 fbac618b e1407279 86b3bbd0
 0340: key          | 79040e57 7ac50486 d0f6930e 160a5c75 fd1203c6
 0360: key          | 3580d2f0 0309a9a8 5effaf02 564fc183 c0183a96
 0380: key          | 38697959 13d3b6db f3b24a1c 7654672c 69a23c35
 0400: key          | 1c0cc52d 7673c52d e9978574 1344662f 5b2308a0

++ ./wormhole vaa dump 0100000001130010b69f83f7d20fec132e915ec891bcbcebc804bcc8390444a30cca23ebd0c47777e332c37ad00906123ee40c667431c5c254c834162b32a074e610f3ca0086690101b6f3f0013226982adc56ab090871961f6472a0ac56ec91ff9fe35bd0f313c06929f1e70bad2a9dca5ee1ca353954d80516a69ccc3bef5f576fceca4676ebe86a0102a90e8a1a6ce4845f44ef441ab102eb1e9242361c01b3de8814db12f6a433e47620b36dc8826fd86dc84d1adaa73684a8ff8904aee5728cea5453bf048a3c31f40003fa21f3244df98345617e4ee27940f05869b3ac1fe4b3ade5df15bddacf55c012020b8eddefb6131a2255450416248e3d420cc73d6830e775c7db17208efbd03d01049871f962cdcb1176b8e430b77b7462e3bd9c24638054ed06170b3bd74056a458445ab6dce2e387745f9d4fc1adee22ec8ae6a133226c92ca3d65ddc71c11ea640005bbfb4e4569e74f8d9f9b39bb0275913a9c959423d3950db2d981fecd63426e4278a6be83507b5c04c8c2b8673f72cee8f752016adec84574409e1ada2c9943770106ac3a0c4d8408934fc1981068cf1e77152ac1ad9620a5f94062700400084331fd2cc880ee14304004ec71e2f94b73bc4cd3486da2a54ee2e68433f7a54574b47100070f36bdd0775ea6d5b086c09af493b42c8f2232cd9475822f94aa5acc4b17737d28d380c0f303a4f4f5f6da06df05fb3c3d8d4aff4aa5abf6875bd5be9cb287370008c8fe42307f7c7bf8a533767a735040c627036440087804b3612b2382aac4a2916d16b4be1458f44892f00dcbe851df248c8f8d2655dcc499ad5513467fca2ef500099f7e548e0ec7a66a08fd8e997f0a9337060d3da5210d479852dad7139100f22c7f1aa145135f63ccfa5844f5c8789971c03322ddb598062bbd951798d70616b7000a60c5aa020c4c36796b7ac11d34fb18b7a9731e29dfbc1bd66a67744a0a8ed679542b63b95e27bfb13f61b735006cad965076e3d3470b2c031115c11f5c810c33000bbf4cf1adbd2c6745b7594c07e77e0dc29739cee5fea9077ce79d2bc3550af2ec5e154b4ed0f3c32a5c2849f5868f0ef99c67ed2f206aa66dbbdd332f1d638769010c204fd08c8031b3c93b1044cf687e3cb693325d778771e4d2b6b198739904f0c5739985b08469d95f13aae75a7815aea817e510418a3079e1a6c1e72b0ad7013e010d2ecf76bdd41c8203f9139627322bb93688e06487aa288550894e1cb8eab13c5e1e0ef5cbc9e777cca213810b18b082ad506fb147e17fda627125647e2bdf5ca0000eb09541e734bbb3e623fff6a130324e9641cc36307ba8a0a9c296475b771e79e076e17965a4341f3faacd46e8d59eb40c304e79103f7afcfdab4572d5997da987000ffe5655d429a73f7d5ab867dfda2bc43ac77fe08129a6879ef497189fe4a8daa0634a2d7d31b158d07c268ca1c33b365a4a8d2c5615fc57cf970a77875fb4f00f0110ab91af9dcf52fbf50afa8c7278cd5308efcb58d40f4aefaff9c4c77af80d28a54bb9c9c4f061644cf5e190bacdc9b705a430ef59159f8585a31c19c9f0849af701111e75afd02f7eb0863e90a057790a2486eca3ca6bd0a5381658bbd2b6c6654dd1353d2ec46a9f5d00a8f76e401f9ac78a8c1412113ce36c84328457069795bfbb011251d60a3754021efa7184d13a2372db2b6a77451092d01e42a78e4725b3d2ee4260520dbcde60944ec59ce0d7f8e8e45cf8d71ffc88f85b800469304ffa979ce50161f3caf30000000300010000000000000000000000000000000000000000000000000000000000000004000000000000000414024523c3F29447d1f32AEa95BEBD00383c4640F1b40000000000000000000000000001085553444300000000000000000000000000000000000000000000000000000000436972636c65436f696e00000000000000000000000000000000000000000000

Dumping VAA, 1411 Bytes

 0000: Version      | 01                              
 0001: Index        | 00000001                        
 0005: Siglen       | 13                              
 0006: Sig 0        | 0010b69f 83f7d20f ec132e91 5ec891bc bcebc804 bcc83904 44a30cca 23ebd0c4 7777e332 c37ad009 06123ee4 0c667431 c5c254c8 34162b32 a074e610 f3ca0086 6901
 0072: Sig 1        | 01b6f3f0 01322698 2adc56ab 09087196 1f6472a0 ac56ec91 ff9fe35b d0f313c0 6929f1e7 0bad2a9d ca5ee1ca 353954d8 0516a69c cc3bef5f 576fceca 4676ebe8 6a01
 0138: Sig 2        | 02a90e8a 1a6ce484 5f44ef44 1ab102eb 1e924236 1c01b3de 8814db12 f6a433e4 7620b36d c8826fd8 6dc84d1a daa73684 a8ff8904 aee5728c ea5453bf 048a3c31 f400
 0204: Sig 3        | 03fa21f3 244df983 45617e4e e27940f0 5869b3ac 1fe4b3ad e5df15bd dacf55c0 12020b8e ddefb613 1a225545 0416248e 3d420cc7 3d6830e7 75c7db17 208efbd0 3d01
 0270: Sig 4        | 049871f9 62cdcb11 76b8e430 b77b7462 e3bd9c24 638054ed 06170b3b d74056a4 58445ab6 dce2e387 745f9d4f c1adee22 ec8ae6a1 33226c92 ca3d65dd c71c11ea 6400
 0336: Sig 5        | 05bbfb4e 4569e74f 8d9f9b39 bb027591 3a9c9594 23d3950d b2d981fe cd63426e 4278a6be 83507b5c 04c8c2b8 673f72ce e8f75201 6adec845 74409e1a da2c9943 7701
 0402: Sig 6        | 06ac3a0c 4d840893 4fc19810 68cf1e77 152ac1ad 9620a5f9 40627004 00084331 fd2cc880 ee143040 04ec71e2 f94b73bc 4cd3486d a2a54ee2 e68433f7 a54574b4 7100
 0468: Sig 7        | 070f36bd d0775ea6 d5b086c0 9af493b4 2c8f2232 cd947582 2f94aa5a cc4b1773 7d28d380 c0f303a4 f4f5f6da 06df05fb 3c3d8d4a ff4aa5ab f6875bd5 be9cb287 3700
 0534: Sig 8        | 08c8fe42 307f7c7b f8a53376 7a735040 c6270364 40087804 b3612b23 82aac4a2 916d16b4 be1458f4 4892f00d cbe851df 248c8f8d 2655dcc4 99ad5513 467fca2e f500
 0600: Sig 9        | 099f7e54 8e0ec7a6 6a08fd8e 997f0a93 37060d3d a5210d47 9852dad7 139100f2 2c7f1aa1 45135f63 ccfa5844 f5c87899 71c03322 ddb59806 2bbd9517 98d70616 b700
 0666: Sig 10       | 0a60c5aa 020c4c36 796b7ac1 1d34fb18 b7a9731e 29dfbc1b d66a6774 4a0a8ed6 79542b63 b95e27bf b13f61b7 35006cad 965076e3 d3470b2c 031115c1 1f5c810c 3300
 0732: Sig 11       | 0bbf4cf1 adbd2c67 45b7594c 07e77e0d c29739ce e5fea907 7ce79d2b c3550af2 ec5e154b 4ed0f3c3 2a5c2849 f5868f0e f99c67ed 2f206aa6 6dbbdd33 2f1d6387 6901
 0798: Sig 12       | 0c204fd0 8c8031b3 c93b1044 cf687e3c b693325d 778771e4 d2b6b198 739904f0 c5739985 b08469d9 5f13aae7 5a7815ae a817e510 418a3079 e1a6c1e7 2b0ad701 3e01
 0864: Sig 13       | 0d2ecf76 bdd41c82 03f91396 27322bb9 3688e064 87aa2885 50894e1c b8eab13c 5e1e0ef5 cbc9e777 cca21381 0b18b082 ad506fb1 47e17fda 62712564 7e2bdf5c a000
 0930: Sig 14       | 0eb09541 e734bbb3 e623fff6 a130324e 9641cc36 307ba8a0 a9c29647 5b771e79 e076e179 65a4341f 3faacd46 e8d59eb4 0c304e79 103f7afc fdab4572 d5997da9 8700
 0996: Sig 15       | 0ffe5655 d429a73f 7d5ab867 dfda2bc4 3ac77fe0 8129a687 9ef49718 9fe4a8da a0634a2d 7d31b158 d07c268c a1c33b36 5a4a8d2c 5615fc57 cf970a77 875fb4f0 0f01
 1062: Sig 16       | 10ab91af 9dcf52fb f50afa8c 7278cd53 08efcb58 d40f4aef aff9c4c7 7af80d28 a54bb9c9 c4f06164 4cf5e190 bacdc9b7 05a430ef 59159f85 85a31c19 c9f0849a f701
 1128: Sig 17       | 111e75af d02f7eb0 863e90a0 57790a24 86eca3ca 6bd0a538 1658bbd2 b6c6654d d1353d2e c46a9f5d 00a8f76e 401f9ac7 8a8c1412 113ce36c 84328457 069795bf bb01
 1194: Sig 18       | 1251d60a 3754021e fa7184d1 3a2372db 2b6a7745 1092d01e 42a78e47 25b3d2ee 4260520d bcde6094 4ec59ce0 d7f8e8e4 5cf8d71f fc88f85b 80046930 4ffa979c e501
 1260: Timestamp    | 61f3caf3                        
 1264: Nonce        | 00000003                        
 1268: Chain        | 0001                            
 1270: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 1302: Sequence     | 00000000 00000004               
 1310: Consistency  | 14                              

Signers (19):

 0000 | 0x52a26c... | Unknown Guardian
 0001 | 0x389a74... | Unknown Guardian
 0002 | 0xb4459e... | Unknown Guardian
 0003 | 0x072491... | Unknown Guardian
 0004 | 0x51280e... | Unknown Guardian
 0005 | 0xfa9aa6... | Unknown Guardian
 0006 | 0xe42d59... | Unknown Guardian
 0007 | 0x4b07ff... | Unknown Guardian
 0008 | 0xc8306b... | Unknown Guardian
 0009 | 0xc8c103... | Unknown Guardian
 0010 | 0x58a250... | Unknown Guardian
 0011 | 0x839082... | Unknown Guardian
 0012 | 0x1fd6e9... | Unknown Guardian
 0013 | 0x255a41... | Unknown Guardian
 0014 | 0xba663b... | Unknown Guardian
 0015 | 0x79040e... | Unknown Guardian
 0016 | 0x3580d2... | Unknown Guardian
 0017 | 0x386979... | Unknown Guardian
 0018 | 0x1c0cc5... | Unknown Guardian

Dumping Digest, 151 Bytes

 0000: Timestamp    | 61f3caf3                        
 0004: Nonce        | 00000003                        
 0008: Chain        | 0001                            
 0010: Emitter      | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
 0042: Sequence     | 00000000 00000004               
 0050: Consistency  | 14                              
 0051: Payload      | 024523c3 f29447d1 f32aea95 bebd0038 3c4640f1 b4000000 00000000 00000000
 0083: Payload      | 00000108 55534443 00000000 00000000 00000000 00000000 00000000 00000000
 0115: Payload      | 00000000 43697263 6c65436f 696e0000 00000000 00000000 00000000 00000000
 0147: Payload      | 00000000                        

Dumping Payload: TokenBridge Attest, 100 Bytes

 0000: Type         | 02                              
 0001: Address      | 4523c3f2 9447d1f3 2aea95be bd00383c 4640f1b4 00000000 00000000 00000000
 0033: Chain        | 0001                            
 0035: decimals     | 08                              
 0036: Symbol       | 55534443 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 0068: Name         | 43697263 6c65436f 696e0000 00000000 00000000 00000000 00000000 00000000



