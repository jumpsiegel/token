            const signedVAA = hexStringToByteArray("0100000000010017fa5858d0e1c87641f5e0f477fd2dec17e1ae8db0c523e196ce87af21810f571315354a17c24c282808a3e72c8f1223b3cce9a35f41ff84d41f0f3e92d384f70061d74a200000e6d20001c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f00000000000000472002165809739240a0ac03b98440fe8985548e3aa683cd0d4d9df5b5659669faa301000109534f4c5400000000000000000000000000000000000000000000000000000000536f6c616e61205465737420546f6b656e000000000000000000000000000000")

# token

The problem:

1) a trusted player deploys master contract (wormhole foundation)

2) untrusted players funds/call "createWrapped" with a on that master contract to create new assets

      The master contract verifies the legitimacy of the payload first
      by looking at signatures from predefined guardians who signed
      it.  That verification is outside the scope of this example  

3) untrusted player calls "redemeWrapped" with a on the master contract to mint from that newly created asset

     Not only do we need to validate the redeme call, we need to do
     duplicate suppression to prevent redeming twice...


source
   <smartContract>  <EmitterChain>   ->   <algo asset>  <smartContract> <EmitterChain>
   <EmitterSource> <SequenceNumber>  ->   <Bit>  (duplicate suppresion)

   <GovernanceIndex (int)> -> <algo app>      19 publicKeys for VAA signers  <32*19>
