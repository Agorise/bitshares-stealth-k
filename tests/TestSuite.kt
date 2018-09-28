import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

object TestSuite {

    var zkconfig = StealthConfig("secp256k1")

    @JvmStatic
    fun main(args: Array<String>) {

        println("Begin Testing Suite:")
        println("")
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

        var bo = BlindOutput(zkconfig, keyPairOTK.public, pubKeyAddr, keyPairOTK.private, false)
        println ("  Shared-secret buffer is: ${bo.sharedsecret.toHexString()}")
        println ("  Shared-secret buffer is: ${bo.sharedsecret.toHexString()}")

        println("")
        println("Test 2: Low-numbered keys:")

        val lowPubKeyAddr = zkconfig.decodePublicKey("02000000000000000000000000000000000000000000000000000000000000879e")
        val lowKeyPairOTK = zkconfig.generateKeyPair(BigInteger("1"))
        val TEST = (lowPubKeyAddr as BCECPublicKey).q as org.bouncycastle.math.ec.ECPoint

        var bo2 = BlindOutput(zkconfig, lowKeyPairOTK.public, lowPubKeyAddr, lowKeyPairOTK.private, false)
        println ("  Shared-secret buffer is: ${bo2.sharedsecret.toHexString()}")
        println ("  Tx Address is: ${bo2.outputPublicKey.toString()}")

        println("Boo yeea!")

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
