import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger

object TestSuite {

    @JvmStatic
    fun main(args: Array<String>) {

        println("Begin Testing Suite:")

        println("Testing BlindCommit:")

        var blindfact = BigInteger("ffff", 16)
        var amount = BigInteger("100")
        var C = StealthZK.BlindCommit(blindfact, amount)

        println("Commitment is (x,y): (${C.xCoord}, ${C.yCoord})")

    }

}
