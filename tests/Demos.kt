import org.bitcoinj.core.ECKey
import org.bouncycastle.util.encoders.Hex

object Demos {

    fun StealthAddress_ProduceAndDecode() {
        println("")
        println("=========================================")
        println("** StealthAddress: Produce and Decode: **")
        println("=========================================")

        println("*\n* Produce New StealthAddress from Randomness:\n*")
        val SA = StealthAddress()
        println("${SA.verboseDescription()}")

        println("*\n* Produce StealthAddresses from ECKeys and public key points:\n*")
        val SA2 = StealthAddress(SA.spendKey.pubKeyPoint)
        println("${SA2.verboseDescription()}")
        val SA3 = StealthAddress(SA.viewKey.pubKeyPoint, SA.spendKey.pubKeyPoint)
        println("${SA3.verboseDescription()}")
        val SA4 = StealthAddress(SA.viewKey, SA.spendKey.pubKeyPoint)
        println("${SA4.verboseDescription()}")

        println("*\n* Decode StealthAddresses from address strings:\n*")
        val SA5 = StealthAddress("BTS7WAmV9w9sBEcewmSN6XDJQiwCxDSLdrfkUaTd6Myhs6U38oDAL")
        println("${SA5.verboseDescription()}")
        val SA6 = StealthAddress("BTSBAyy4fqVtRyseqpPdD1iq9nwJtt12w3RNzsv2pTsT3KNFNVVsrPTjZjCEhCBmcyKgGo6Dk6YDZHx7RQGtK7rgNJDKHqAfNR")
        println("${SA6.verboseDescription()}")

        println("*\n* CONCLUDES: DEMO: StealthAddress_ProduceAndDecode.")
        println("* ////////\n")

    }

    fun StealthAddress_SendAndReceive() {
        println("")
        println("========================================")
        println("** StealthAddress: Send and Receive:  **")
        println("========================================")

        val SA_Bob_with_Priv = StealthAddress()
        val Bob_address = SA_Bob_with_Priv.address
        val SA_Bob = StealthAddress(Bob_address)

        println("*\n*  Bob publishes a Stealth Address to his social media site:\n*")
        println("*    Bob Address:  ${Bob_address}\n*")
        println("*  Bob's address encodes a public ViewKey and public SpendKey:\n*")
        println("*        ViewKey:  ${SA_Bob.viewKey.publicKeyAsHex}")
        println("*       SpendKey:  ${SA_Bob.spendKey.publicKeyAsHex}\n*")


        println("*\n*  Alice wishes to send a balance to Bob.  Alice generates one-time randomness key OTK:\n*")

        val OTK = ECKey()
        val OTK_string = PrefixBase58Check("OTK", OTK.pubKey)

        println("*            OTK:  ${OTK_string},")
        println("*                  (${OTK.publicKeyAsHex})\n*")
        println("*  for which she possesses private key: ${OTK.privateKeyAsHex}.\n*")

        val TxAuthKeyPub = StealthAddress(Bob_address).getTxAuthKey(OTK)
        val TxAuth_string = PrefixBase58Check("BTS",TxAuthKeyPub.pubKey)

        println("*  With the OTK private key, Alice is able to generate TxAuthKey as a child between OTK and Bob's address.\n*")
        println("*      TxAuthKey:  ${TxAuth_string}")
        println("*                  (${TxAuthKeyPub.publicKeyAsHex})\n*")
        println("*  She publishes her transaction to the network, including (OTK, TxAuthKey) in the metadata.")
        println("*  Two other players publish unrelated transactions in the same time window, such that Bob's")
        println("*  wallet observes the following transaction metadata packets on the network:\n*")

        val Herring1_OTK = ECKey()
        val Herring1_TAK = ECKey()
        val Herring2_OTK = ECKey()
        val Herring2_TAK = ECKey()

        println("*   1. (${OTK_string}, ${TxAuth_string})")
        println("*   2. (${PrefixBase58Check("OTK",Herring1_OTK.pubKey)}, ${PrefixBase58Check("BTS",Herring1_TAK.pubKey)})")
        println("*   3. (${PrefixBase58Check("OTK",Herring2_OTK.pubKey)}, ${PrefixBase58Check("BTS",Herring2_TAK.pubKey)})")
        println("*")

        println("*  Bob checks each (OTK,TxAuthKey) pair to see if his address generates the same TxAuthKey from")
        println("*  the OTK, and succeeds in recognizing the one from Alice.\n*")

        fun MatchOrNoMatch(otk : ECKey, txakey : ECKey) : String {
            return if(SA_Bob_with_Priv.recognizeTxAuthKey(otk, txakey))
            {"Match! Incoming funds recognized!"} else
            {"not recognized"}
        }

        println("*   1. ${MatchOrNoMatch(OTK, TxAuthKeyPub)}")
        println("*   2. ${MatchOrNoMatch(Herring1_OTK, Herring1_TAK)}")
        println("*   3. ${MatchOrNoMatch(Herring2_OTK, Herring2_TAK)}")

        println("*\n* CONCLUDES: DEMO: StealthAddress_SendAndReceive")
        println("* ////////\n")

    }

    fun PrefixBase58Check_Encoding() {
        println("")
        println("=======================================")
        println("** PrefixBase58Check: Encoding Demo: **")
        println("=======================================")
        println("*\n* Encoding Simple Byte Sequences, using payloads D and prefix 'BTS.'.")
        println("*")

        println("D = \"\":                 ${PrefixBase58Check("BTS.")}")
        println("D = 0x00:               ${PrefixBase58Check("BTS.", ByteArray(1, {0}))}")
        println("D = 0x0000:             ${PrefixBase58Check("BTS.", ByteArray(2, {0}))}")
        println("D = 0x000000:           ${PrefixBase58Check("BTS.", ByteArray(3, {0}))}")
        println("D = 0x00000000:         ${PrefixBase58Check("BTS.", ByteArray(4, {0}))}")
        println("D = 0x0000000000:       ${PrefixBase58Check("BTS.", ByteArray(5, {0}))}")
        println("D = 0x000000000000:     ${PrefixBase58Check("BTS.", ByteArray(6, {0}))}")
        println("D = 0x01:               ${PrefixBase58Check("BTS.", ByteArray(1, {1}))}")
        println("D = 0x0101:             ${PrefixBase58Check("BTS.", ByteArray(2, {1}))}")
        println("D = 0x010101:           ${PrefixBase58Check("BTS.", ByteArray(3, {1}))}")
        println("D = 0x01010101:         ${PrefixBase58Check("BTS.", ByteArray(4, {1}))}")
        println("D = 0x0101010101:       ${PrefixBase58Check("BTS.", ByteArray(5, {1}))}")
        println("D = 0x010101010101:     ${PrefixBase58Check("BTS.", ByteArray(6, {1}))}")
        println("D = 0xCCCC00:             ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(1, {0}))}")
        println("D = 0xCCCC0000:           ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(2, {0}))}")
        println("D = 0xCCCC000000:         ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(3, {0}))}")
        println("D = 0xCCCC00000000:       ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(4, {0}))}")
        println("D = 0xCCCC0000000000:     ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(5, {0}))}")
        println("D = 0xCCCC000000000000:   ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(6, {0}))}")
        println("D = 0xCCCC111111111111:   ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(6, {17}))}")
        println("D = 0xCCCC222222222222:   ${PrefixBase58Check("BTS.", ByteArray(2,{-52})+ByteArray(6, {34}))}")
        println("D = 0x0488B21E00:         ${PrefixBase58Check("BTS.", Hex.decode("0488B21E") + ByteArray(1, {0}))}")
        println("D = 0x0488B21E0000:       ${PrefixBase58Check("BTS.", Hex.decode("0488B21E") + ByteArray(2, {0}))}")
        println("D = 0x0488B21E00000000:   ${PrefixBase58Check("BTS.", Hex.decode("0488B21E") + ByteArray(4, {0}))}")
        println("D = 0x0488B21E00...00:    ${PrefixBase58Check("BTS.", Hex.decode("0488B21E") + ByteArray(8, {0}))}")
        println("D = 0x0488B21E00...00:    ${PrefixBase58Check("BTS.", Hex.decode("0488B21E") + ByteArray(16, {0}))}")
        println("D = 0x0488B21E00...00:    ${PrefixBase58Check("BTS.", Hex.decode("0488B21E") + ByteArray(74, {0}))}")
        val SA = StealthAddress()   //
        val SA2 = StealthAddress()  // Generating addresses just to get the keys...
        val SA3 = StealthAddress()  //
        println("*")
        println("* Encoding Public Keys:\n*")
        println("D = [Pub1][Pub2]:       ${PrefixBase58Check("BTS.", SA.viewKey.pubKey + SA.spendKey.pubKey)}")
        println("D = [Pub2][Pub2]:       ${PrefixBase58Check("BTS.", SA.spendKey.pubKey + SA.spendKey.pubKey)}")
        println("D = [Pub2][Pub1]:       ${PrefixBase58Check("BTS.", SA.spendKey.pubKey + SA.viewKey.pubKey)}")
        println("D = [Pub2][Pub3]:       ${PrefixBase58Check("BTS.", SA.spendKey.pubKey + SA2.spendKey.pubKey)}")
        println("D = [Pub2][Pub4]:       ${PrefixBase58Check("BTS.", SA.spendKey.pubKey + SA2.viewKey.pubKey)}")
        println("D = [Pub1]:             ${PrefixBase58Check("BTS.", SA.viewKey.pubKey)}")
        println("D = [Pub2]:             ${PrefixBase58Check("BTS.", SA.spendKey.pubKey)}")
        println("D = [Pub3]:             ${PrefixBase58Check("BTS.", SA2.viewKey.pubKey)}")
        println("D = [Pub4]:             ${PrefixBase58Check("BTS.", SA2.spendKey.pubKey)}")
        println("D = [Pub5]:             ${PrefixBase58Check("BTS.", SA3.viewKey.pubKey)}")
        println("D = [Pub6]:             ${PrefixBase58Check("BTS.", SA3.spendKey.pubKey)}")

        println("*\n* CONCLUDES: DEMO: PrefixBase58Check_Encoding.")
        println("* ////////\n")

    }


}