import org.bitcoinj.core.ECKey
import org.bouncycastle.util.encoders.Hex
import org.spongycastle.math.ec.ECPoint
import java.math.BigInteger

object TestSuite {

    var zkconfig = StealthConfig("secp256k1")

    @JvmStatic
    fun main(args: Array<String>) {

        println("Begin Testing Suite:")
        println("")

        //TestBlindCommitment()
        //TestPointNegation()
        //TestECKeyPairGeneration()
        Test_PrefixBase58Check_Encoding()
        Test_PrefixBase58Check_Decoding()
        Test_StealthAddress_ProduceAndDecode()
        Test_StealthAddress_SendAndReceive()

    }

    /*  **************************************
     *  TESTS:
     */

    @JvmStatic
    fun TestBlindCommitment() {
        println("Testing BlindCommitment:")

        TestBlindCommit(BigInteger("FFFF", 16),
                arrayOf(BigInteger("100")),
                "Normal randomness and value")
        TestBlindCommit(BigInteger("FFFF", 16),
                arrayOf(BigInteger("0")),
                "Value message is zero")
        TestBlindCommit(BigInteger("FFFF", 16),
                arrayOf<BigInteger>(),
                "Value array is empty")
        TestBlindCommit(zkconfig.curveOrder.add(BigInteger("-1")),
                arrayOf(BigInteger("100")),
                "Randomness is almost curve order")
        TestBlindCommit(BigInteger("7"),
                arrayOf(BigInteger("0")),
                "These two should have same X but opposite Y")
        TestBlindCommit(zkconfig.curveOrder.add(BigInteger("-7")),
                arrayOf(BigInteger("0")),
                "These two should have same X but opposite Y")
        TestBlindCommitSneakyException(BigInteger("1"),
                arrayOf(BigInteger("1")),
                "Sneaky Null commit")
        TestBlindCommitException(BigInteger("0"),
                arrayOf(BigInteger("100")),
                "Randomness is zero")
        TestBlindCommitException(zkconfig.curveOrder,
                arrayOf(BigInteger("100")),
                "Randomness is curve order")
        TestBlindCommitException(BigInteger("FFFF", 16),
                arrayOf(zkconfig.curveOrder),
                "Value message is curve order")
        TestBlindCommitException(BigInteger("FFFF", 16),
                arrayOf(BigInteger("100"), BigInteger("200")),
                "Too many values for generators")
    }

    @JvmStatic
    fun TestPointNegation() {

        /* Next test if the various ways to "negate" a point are indeed equivalent.
           I.e., does -2*G == -(2*G) == (N-2)*G ?
           Answer: It DOES, but might not look like it since ECPoint uses an internal Z-coordinate
           that can flip the meaning of the sign on the stored Y-coordinate.  If we output hex-encoded
           points instead, we see the expected behavior.  Addendum: Or we can normalize() points.
         */

        println("")
        println("Testing understanding of point negation:")

        var N = zkconfig.curveOrder
        var G = zkconfig.G
        println("Curve order N is ${N}")

        for (i in 1..3) {
            //println("")
            println("For i = ${i}:")

            var iBI = i.toBigInteger()
            var niBI = (-i).toBigInteger()
            var NiBI = N.subtract(iBI)

            var iG = G.multiply(iBI)
            var niG = G.multiply(niBI)
            var NiG = G.multiply(NiBI)

            /* Note: Run this test outputing hex encoded points. If you display xCoord and yCoord explicitly, you
               will get weird-seeming results owing to the implied z-coordinate in the internal representation.
             */

            println("    i * G   ${Hex.toHexString(iG.getEncoded(true))}  mult: ${iBI}")
            println("   -i * G   ${Hex.toHexString(niG.getEncoded(true))}  mult: ${niBI}")
            println(" (N-i)* G   ${Hex.toHexString(NiG.getEncoded(true))}  mult: ${NiBI}")
        }

    }

    @JvmStatic
    fun TestECKeyPairGeneration() {
        println("")
        println("Testing Generation of EC Key Pairs:")
        println("***********************************")
        println("")

        println("Test 1: Randomly generated keys:")

        var keyPairOTK = zkconfig.generateKeyPair()
        var (pubKeyAddr) = zkconfig.generateKeyPair()

        println("  Generated Key A:")
        println("  Public: ${keyPairOTK.public.toString()}")
        println("  Private: ${keyPairOTK.private.toString()}")
        println("  Generated Key B:")
        println("  Public: ${pubKeyAddr.toString()}")

    }

    @JvmStatic
    fun Test_PrefixBase58Check_Encoding() {
        println("")
        println("=======================================")
        println("** PrefixBase58Check: Encoding Test: **")
        println("=======================================")
        println("*\n* Encoding Simple Byte Sequences:\n*")
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
        var SA = StealthAddress()   //
        var SA2 = StealthAddress()  // Generating addresses just to get the keys...
        var SA3 = StealthAddress()  //
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
        println("*\n* Concludes Test_PrefixBase58Check_Encoding.\n*\n")
    }

    @JvmStatic
    fun Test_PrefixBase58Check_Decoding() {
        println("")
        println("=======================================")
        println("** PrefixBase58Check: Decoding Test: **")
        println("=======================================")

        fun Do_Test(inpStr : String, shouldPfx : String, shouldPayloadHex : String) : Unit {
            try {
                val PB = PrefixBase58Check.fromString(inpStr)
                val prefix = PB.prefix
                val payloadHex = PB.payload.toHexString()
                val testResult = if(prefix.contentEquals(shouldPfx) && payloadHex.contentEquals(shouldPayloadHex))
                                 {"PASS"} else {"FAIL"}
                println("${testResult}: For input: ${inpStr.padEnd(20,' ')} Prefix is: ${prefix.padEnd(4,' ')} Payload is ${payloadHex}") }
            catch (e: Throwable) {
                println("FAIL: Input ${inpStr} resulted in unanticipated exception ${e}")
            }
        }
        fun Do_Test_Except(inpStr : String, reason: String = "") {
            try {
                val PB = PrefixBase58Check.fromString(inpStr)
                val reasonStr = if(reason.isNotBlank()) {" (${reason})"} else {""}
                println("FAIL: Input '${inpStr}' did NOT result in expected exception.${reasonStr}") }
            catch(e: Throwable) {
                val reasonStr = if(reason.isNotBlank()) {" (${reason})"} else {""}
                println("PASS: Input: ${("'"+inpStr+"'").padEnd(22,' ')} produced expected exception.${reasonStr}")
            }
        }

        println("*\n* Decoding Simple Byte Sequences:\n*")

        Do_Test("BTS4zNxKW", "BTS", "")
        Do_Test("GRPH4zNxKW", "GRPH", "")
        Do_Test("BTS11115BhVPG", "BTS", "00000000")
        Do_Test("BTS111115BhVPG", "BTS1", "00000000")  // "Looks like" too many 1's but extra 1 interprets as prefix
        Do_Test("GRPH11115BhVPG", "GRPH", "00000000")
        Do_Test("BTSAjsziuRxrX", "BTS", "01010101")

        Do_Test_Except("PrefixTooLong4zNxKW")
        Do_Test_Except("BTS4zNxKWy", "Added extra char")
        Do_Test_Except("BTS4zNxKX", "Changed char")
        Do_Test_Except("prfx1111115BhVPG", "Too many leading ones")
        Do_Test_Except("prfx111115BhVPG", "Too many leading ones")
        Do_Test_Except("prfx1115BhVPG", "Too few leading ones")
        Do_Test_Except(" BTSAjsziuRxrX", "Whitespace")
        Do_Test_Except("BTS AjsziuRxrX", "Whitespace")
        Do_Test_Except("BTSAjsziuRxrX ", "Whitespace")

        println("*\n* Decoding Public Key Payloads:\n*")
        Do_Test("BTS5WcAwQDaxCVDLYgUcBPHJJx8nxKquQCxRBsezN2DQnJ7Ha2VxU",
                "BTS", "025202641a11502db19165dc6b4c2703f76a2016978cf9e4257db32bc435834f49")
        Do_Test("BTS8UYgAf3C7yj2Sq5mrPtGNf4sKtS7spBsL1C5Pzj2zATTiC1Beh",
                "BTS", "03d86b6558850e986fcd756e0e70b6d3c0dab426b7f2bab34bca99874201fa9f47")

        println("*\n* Concludes Test_PrefixBase58Check_Decoding.\n*\n")

    }

    @JvmStatic
    fun Test_StealthAddress_ProduceAndDecode() {
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

        println("*\n* Concludes Test_StealthAddress_ProduceAndDecode.\n* //////\n")

    }

    @JvmStatic
    fun Test_StealthAddress_SharedSecrets() {
        println("")
        println("=======================================")
        println("** StealthAddress: Shared Secrets:   **")
        println("=======================================")

        var SA = StealthAddress()

        println("${SA.verboseDescription()}")
        println("${SA}")

        val OTK = ECKey()
        println("\nOTK: ${OTK}")
        println("Shared X:      ${SA.getSharedXCoord(OTK).toHexString()}")
        println("Shared Secret: ${SA.getSharedSecret(OTK).toHexString()}")
        println("Child PubKey:  ${SA.getTxAuthKey(OTK).pubKey.toHexString()}")

        println("*\n* Concludes Test_StealthAddress_SharedSecrets.\n*\n")

    }

    @JvmStatic
    fun Test_StealthAddress_SendAndReceive() {
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

        println("*\n* CONCLUDES: Test_StealthAddress_SendAndReceive")
        println("* ////////\n")

    }

        /*  **************************************
         *  HELPER FUNCTIONS FOLLOW:
         */

    @JvmStatic
    fun TestBlindCommit(blind: BigInteger, values: Array<BigInteger>, label: String) {

        var commit =  BlindCommitment(zkconfig, blind, values)
        var C = commit.getECCommitment()
        C = C.normalize()  // Prevent weirdness from degeneracy of representation

        println("Commitment is (x,y): (${C.xCoord}, ${C.yCoord}) :: ${label}")

    }

    @JvmStatic
    fun TestBlindCommitException(blind: BigInteger, values: Array<BigInteger>, label: String) {

        try {
            var commit = BlindCommitment(zkconfig, blind, values)
            var C = commit.getECCommitment()
            C = C.normalize()  // Prevent weirdness from degeneracy of representation

            println("Commitment is (x,y): (${C.xCoord}, ${C.yCoord}) :: ${label}")
            println("Whoops! An exception should have been thrown!")
        } catch(e: Throwable){
            println("Caught Expected Exception (Tried: ${label}; Got: ${e.message})")
        }
    }

    @JvmStatic
    fun TestBlindCommitSneaky(blind: BigInteger, values: Array<BigInteger>, label: String) {

        var commit =  BlindCommitment(zkconfig, blind, values, arrayOf(zkconfig.G.negate()))
        var C = commit.getECCommitment()
        C = C.normalize()  // Prevent weirdness from degeneracy of representation

        println("Commitment is (x,y): (${C.xCoord}, ${C.yCoord}) :: ${label}")

    }

    @JvmStatic
    fun TestBlindCommitSneakyException(blind: BigInteger, values: Array<BigInteger>, label: String) {

        try {
            var commit = BlindCommitment(zkconfig, blind, values, arrayOf(zkconfig.G.negate()))
            var C = commit.getECCommitment()
            C = C.normalize()  // Prevent weirdness from degeneracy of representation

            println("Commitment is (x,y): (${C.xCoord}, ${C.yCoord}) :: ${label}")
            println("Whoops! An exception should have been thrown!")
        } catch(e: Throwable){
            println("Caught Expected Exception (Tried: ${label}; Got: ${e.message})")
        }
    }

}
