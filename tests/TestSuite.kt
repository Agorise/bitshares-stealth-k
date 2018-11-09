import org.bitcoinj.core.ECKey
import org.bouncycastle.util.encoders.Hex
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
        //TestPrefixBase58Check()

        var SA = StealthAddress()

        println("${SA.verboseDescription()}")
        println("${SA}")

        val OTK = ECKey()
        println("\nOTK: ${OTK}")
        println("Shared X:      ${SA.getSharedXCoord(OTK).toHexString()}")
        println("Shared Secret: ${SA.getSharedSecret(OTK).toHexString()}")
        println("Child PubKey:  ${SA.getTxAuthKey(OTK).pubKey.toHexString()}")

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
    fun TestPrefixBase58Check() {

        var SA = StealthAddress()
        var SA2 = StealthAddress()
        var SA3 = StealthAddress()

        println("\nPrefixBase58Check test:\n")
        println("D = \"\":                 ${PrefixBase58Check("BTS.")}")
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
