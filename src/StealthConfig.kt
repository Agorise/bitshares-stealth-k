import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger
import java.security.*
import java.security.PrivateKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

/* Kind of a hack, but the following allows destructuring of the components of a KeyPair object, e.g. when
 * returned from StealthConfig.GenerateKeyPair().  By "kind of a hack," I mean, this works, but is probably
 * the WRONG place to make this extension to the KeyPair class. Goal is to get the Kotlin-like behavior
 * (destructurability) from this Java class. But defining the extension here will likely at some point
 * conflict with a similar extension placed elsewhere.
 *
 * Allows for:  val (pub, priv) = config.GenerateKeyPair();
 * instead of:  val keypair = config.GenerateKeyPair(); val pub = keypair.public; //...
 */
operator fun KeyPair.component1() : PublicKey {return this.public}
operator fun KeyPair.component2() : PrivateKey {return this.private}

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

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    val ecNamedSpec = ECNamedCurveTable.getParameterSpec(curvename)
    val ecSpec : ECParameterSpec = ECNamedCurveSpec(curvename, ecNamedSpec.curve, ecNamedSpec.g, ecNamedSpec.n, ecNamedSpec.h, ecNamedSpec.seed);
    // Curve Specs from table

    val G : ECPoint = ecNamedSpec.g as ECPoint
    // secp256k1 Generator G

    val G2 = ecNamedSpec.curve.decodePoint(Hex.decode("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
    // This one is the "alternate" generator proposed by Maxwell, et al, for Confidential Transactions
    // x: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    // y: "31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904"

    val maxProvable = BigInteger( "FFFFFFFFFFFFF", 16)
    // Range proofs and commitments should reject amounts larger than this. This should be chosen to match target
    // platform.  Example: enough bits to represent max value of token.  Or an explicit ma value (e.g. BitShares
    // has a MAX_SUPPLY which is a power of ten, rather than a power of two.)

    val curveOrder : BigInteger get() = ecNamedSpec.n

    /**
     * Simple Key Pair Generator that returns a key pair on the correct curve config.
     */
    fun generateKeyPair() : KeyPair {
        val g = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
        g.initialize(this.ecSpec, SecureRandom())
        return g.generateKeyPair()
    }

    /**
     *   Generate a Key Pair from a known private key secret integer
     */
    fun generateKeyPair(d : BigInteger) : KeyPair {
        val fact = KeyFactory.getInstance("ECDH", "BC")
        val pubKeySpec = ECPublicKeySpec(
                ECPointUtil.decodePoint(  // BC ECPoint and Java ECPoint are not same... encode/decode to "cast"
                        this.ecSpec.curve,
                        this.G.multiply(d).getEncoded(true)),
                this.ecSpec)
        val pubKey =  fact.generatePublic(pubKeySpec)
        val privKeySpec = ECPrivateKeySpec(d,this.ecSpec)
        val privKey = fact.generatePrivate(privKeySpec)
        return KeyPair(pubKey, privKey)
    }

    /**
     *  This will decode a PublicKey object from a hex string assumed to represent a key on the
     *  current curve in compressed ("02xxxx") or uncompressed ("04xxxxyyyy") format.
     */
    fun decodePublicKey(encoded : String) : PublicKey {
        val fact = KeyFactory.getInstance("ECDH", "BC")
        val pubKeySpec = ECPublicKeySpec(
                ECPointUtil.decodePoint(
                        this.ecSpec.curve,
                        Hex.decode(encoded)),
                this.ecSpec)
        return fact.generatePublic(pubKeySpec)
    }

}
