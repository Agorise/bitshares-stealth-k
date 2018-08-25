import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger

/**
 *  Class StealthConfig
 *
 *  Here we declare a set of config options that will be common to all other Stealth objects in this library.
 *  Although currently designing to a Confidential Transactions implementation, I am keeping in mind future
 *  adaptation to Confidential Assets and MimbleWimble, as best I can at this time.
 *
 *  Things like... What curve are we using?  What is the maximum provable value we want to allow in range
 *  proofs and commitments, etc.
 *
 *  Usage: instantiate one of these and set platform parameters; pass to construction of other objects.
 */

class StealthConfig(curvename: String) {

    val ecSpec = ECNamedCurveTable.getParameterSpec(curvename)
    // Curve Specs from table

    val G : ECPoint = ecSpec.g
    // secp256k1 Generator G

    val G2 = ecSpec.curve.decodePoint(Hex.decode("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
    // This one is the "alternate" generator proposed by Maxwell, et al, for Confidential Transactions
    // x: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    // y: "31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904"

    val maxProvable = BigInteger( "FFFFFFFFFFFFF", 16)
    // Range proofs and commitments should reject amounts larger than this. This should be chosen to match target
    // platform.  Example: enough bits to represent max value of token.  Or an explicit ma value (e.g. BitShares
    // has a MAX_SUPPLY which is a power of ten, rather than a power of two.)

    val curveOrder : BigInteger get() = ecSpec.n

}
