
// npx prettier --write .

const web3EthAbi = require("web3-eth-abi");
const web3Utils = require("web3-utils");
const elliptic = require("elliptic");

const guardianKeys = [
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
];

const guardianPrivKeys = [
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
];

class GenTest {
  /**
   * Create a packed and signed VAA for testing.
   * See https://github.com/certusone/wormhole/blob/dev.v2/design/0001_generic_message_passing.md
   *
   * @param {} guardianSetIndex  The guardian set index
   * @param {*} signers The list of private keys for signing the VAA
   * @param {*} timestamp The timestamp of VAA
   * @param {*} nonce The nonce.
   * @param {*} emitterChainId The emitter chain identifier
   * @param {*} emitterAddress The emitter chain address, prefixed with 0x
   * @param {*} sequence The sequence.
   * @param {*} consistencyLevel  The reported consistency level
   * @param {*} payload This VAA Payload hex string, prefixed with 0x
   */
  createSignedVAA(
    guardianSetIndex,
    signers,
    timestamp,
    nonce,
    emitterChainId,
    emitterAddress,
    sequence,
    consistencyLevel,
    target,
    payload
  ) {
    const body = [
      web3EthAbi.encodeParameter("uint32", timestamp).substring(2 + (64 - 8)),
      web3EthAbi.encodeParameter("uint32", nonce).substring(2 + (64 - 8)),
      web3EthAbi
        .encodeParameter("uint16", emitterChainId)
        .substring(2 + (64 - 4)),
      web3EthAbi.encodeParameter("bytes32", emitterAddress).substring(2),
      web3EthAbi.encodeParameter("uint64", sequence).substring(2 + (64 - 16)),
      web3EthAbi
        .encodeParameter("uint8", consistencyLevel)
        .substring(2 + (64 - 2)),
      payload,
    ];

    const hash = web3Utils.keccak256(web3Utils.keccak256("0x" + body.join("")));

    // console.log('VAA body Hash: ', hash)

    let signatures = "";

    for (const i in signers) {
      // eslint-disable-next-line new-cap
      const ec = new elliptic.ec("secp256k1");
      const key = ec.keyFromPrivate(signers[i]);
      const signature = key.sign(hash.substr(2), { canonical: true });

      const packSig = [
        web3EthAbi.encodeParameter("uint8", i).substring(2 + (64 - 2)),
        this.zeroPadBytes(signature.r.toString(16), 32),
        this.zeroPadBytes(signature.s.toString(16), 32),
        web3EthAbi
          .encodeParameter("uint8", signature.recoveryParam)
          .substr(2 + (64 - 2)),
      ];

      signatures += packSig.join("");
    }

    const vm = [
      web3EthAbi.encodeParameter("uint8", 1).substring(2 + (64 - 2)),
      web3EthAbi .encodeParameter("uint32", guardianSetIndex) .substring(2 + (64 - 8)),
      web3EthAbi .encodeParameter("uint8", signers.length) .substring(2 + (64 - 2)),

      signatures,
      body.join(""),
    ].join("");

    return vm;
  }

  zeroPadBytes(value, length) {
    while (value.length < 2 * length) {
      value = "0" + value;
    }
    return value;
  }

  zeroPadString(symbol, length) {
      let sy = ""
      // There is probably a better way of doing this.. *shrug*
      for (const i in symbol) {
          sy += web3EthAbi.encodeParameter("uint8", symbol.charCodeAt(i)).substring(64);
      }
      let i = 0;
      while (i < (32 - (symbol.length))) {
          sy = sy + "00";
          i += 1;
      }
      return sy;
  }

  shuffle(array) {
    let currentIndex = array.length;
    let randomIndex;

    // While there remain elements to shuffle...
    while (currentIndex !== 0) {
      // Pick a remaining element...
      randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;

      // And swap it with the current element.
      [array[currentIndex], array[randomIndex]] = [
        array[randomIndex],
        array[currentIndex],
      ];
    }

    return array;
  }

  //// GuardianSetUpgrade is a VAA that instructs an implementation to upgrade the current guardian set
  //GuardianSetUpgrade struct {
  //    // Core Wormhole Module
  //    Module [32]byte = "Core"
  //    // Action index (2 for GuardianSet Upgrade)
  //    Action uint8 = 2
  //    // This update is chain independent
  //    Chain uint16 = 0
  //
  //    // New GuardianSet
  //    NewGuardianSetIndex uint32
  //    // New GuardianSet
  //    NewGuardianSetLen u8
  //    NewGuardianSet []Guardian
  //}

  genGuardianSetUpgrade(signers, guardianSet, targetSet, nonce, seq) {
    let body = [
      this.zeroPadBytes("", 28),
      web3EthAbi.encodeParameter("uint8", "C".charCodeAt(0)).substring(64),
      web3EthAbi.encodeParameter("uint8", "o".charCodeAt(0)).substring(64),
      web3EthAbi.encodeParameter("uint8", "r".charCodeAt(0)).substring(64),
      web3EthAbi.encodeParameter("uint8", "e".charCodeAt(0)).substring(64),
      web3EthAbi.encodeParameter("uint8", 2).substring(64),
      web3EthAbi.encodeParameter("uint16", 0).substring(2 + (64 - 4)),
      web3EthAbi.encodeParameter("uint32", targetSet).substring(2 + (64 - 8)),
      web3EthAbi.encodeParameter("uint8", guardianKeys.length).substring(64),
    ].join("");

    for (const i in guardianKeys) {
      body += guardianKeys[i];
    }

    const emitter = "0x" + this.zeroPadBytes("", 31) + "04"; // Is the emitter of a guardian upgrade 0?

    return this.createSignedVAA(
      guardianSet,
      signers,
      Math.round(new Date().getTime() / 1000),
      nonce,
      1,
      emitter,
      seq,
      0,
      0,
      body
    );
  }

  // AssetMeta:

  //```
  //PayloadID uint8 = 2
  //// Address of the token. Left-zero-padded if shorter than 32 bytes
  //TokenAddress [32]uint8
  //// Chain ID of the token
  //TokenChain uint16
  //// Number of decimals of the token
  //// (the native decimals, not truncated to 8)
  //Decimals uint8
  //// Symbol of the token (UTF-8)
  //Symbol [32]uint8
  //// Name of the token (UTF-8)
  //Name [32]uint8
  //```

  genAssetMeta(signers, guardianSet, nonce, seq, tokenAddress, symbol, name) {
      let ta = tokenAddress
      let i = 0;
      while (i < (32 - (tokenAddress.length/2))) {
          ta = ta + "00";
          i += 1;
      }

      let sy = this.zeroPadString(symbol);
      let nm = this.zeroPadString(name);


    let body = [
        web3EthAbi.encodeParameter("uint8", 2).substring(64),
        ta,
        web3EthAbi.encodeParameter("uint16", 1).substring(2 + (64 - 4)), // comes from solana
        web3EthAbi.encodeParameter("uint8", 8).substring(64),  // Number of decimals of the token
        sy,
        nm
        ].join("");

    const emitter = "0x" + this.zeroPadBytes("", 31) + "04"; // Is the emitter of a guardian upgrade 0?

    return this.createSignedVAA(
      guardianSet,
      signers,
      Math.round(new Date().getTime() / 1000),
      nonce,
      1,
      emitter,
      seq,
      20,
      0,
      body
    );
  }

//Transfer:
//
//PayloadID uint8 = 1
//   Amount being transferred (big-endian uint256)
//Amount uint256
//   Address of the token. Left-zero-padded if shorter than 32 bytes
//TokenAddress bytes32
//   Chain ID of the token
//TokenChain uint16
//   Address of the recipient. Left-zero-padded if shorter than 32 bytes
//To bytes32
//   Chain ID of the recipient
//ToChain uint16
//   Amount of tokens (big-endian uint256) that the user is willing to pay as relayer fee. Must be <= Amount.
//Fee uint256

  genTransfer(signers, guardianSet, nonce, seq, tokenAddress, amt) {
      let ta = tokenAddress
      let i = 0;
      while (i < (32 - (tokenAddress.length/2))) {
          ta = ta + "00";
          i += 1;
      }

    let body = [
        web3EthAbi.encodeParameter("uint8", 1).substring(64),
        web3EthAbi.encodeParameter("uint256", parseInt(amt * (100000000))).substring(2),
        ta,
        web3EthAbi.encodeParameter("uint16", 1).substring(2 + (64 - 4)), // comes from solana
        ta,  // This is the address of receptiant 
        web3EthAbi.encodeParameter("uint16", 8).substring(2 + (64 - 4)), // comes from solana
        web3EthAbi.encodeParameter("uint256", parseInt(0)).substring(2)
        ].join("");

    console.log(body.length)

    const emitter = "0x" + this.zeroPadBytes("", 31) + "04"; // Is the emitter of a guardian upgrade 0?

    return this.createSignedVAA(
      guardianSet,
      signers,
      Math.round(new Date().getTime() / 1000),
      nonce,
      1,
      emitter,
      seq,
      20,
      0,
      body
    );
  }
          

  test() {
//      console.log("./wormhole vaa dump " + this.genGuardianSetUpgrade(guardianPrivKeys, 1, 1, 1, 1));
//      console.log("./wormhole vaa dump " + this.genGuardianSetUpgrade(guardianPrivKeys, 1, 2, 2, 2));
//      console.log("./wormhole vaa dump " + this.genAssetMeta(guardianPrivKeys, 2, 3, 4, "4523c3F29447d1f32AEa95BEBD00383c4640F1b4", "USDC", "CircleCoin"))
//      console.log(this.genAssetMeta(guardianPrivKeys, 2, 4, 5, "4523c3F29447d1f32AEa95BEBD00383c4640F1b4", "USDC", "CircleCoin"))
      console.log(this.genTransfer(guardianPrivKeys, 2, 5, 6, "4523c3F29447d1f32AEa95BEBD00383c4640F1b4", 1))
  }
}

const genTest = new GenTest();

genTest.test();
