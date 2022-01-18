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
