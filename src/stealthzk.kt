import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger

/**@file
 *
 *  This is the BEGINNING of a Kotlin implementation of
 *  Zero-Knowledge primatives on the secp256k1 EC curve.  It is NOT
 *  hardened and should NOT be considered SECURE, nor even
 *  mathematically CORRECT.
 *
 *  For now, the ONLY purpose for this is for prototyping
 *  javascript-based UI wallets implementing blinded and/or stealth
 *  transactions.
 *
 *  This library is loosely based on
 *  https://github.com/bitshares/secp256k1-zkp, followed by:
 *  https://github.com/Agorise/bitshares-ui/blob/bitshares/web/app/stealth/Transfer/stealthzk.js
 *
 *  To my knowledge, no native Kotlin implementation of
 *  secp256k1-zkp exists.
 *  https://github.com/eosio/eosjs-secp256k1.  I am uncertain as to
 *  the state of this project, however.
 *
 */
object StealthZK{

    val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    // Curve Specs from table

    val G : ECPoint = ecSpec.g
    // secp256k1 Generator G

    val G2 = ecSpec.curve.decodePoint(Hex.decode("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
    // This one is the "alternate" generator proposed by Maxwell, et al, for Confidential Transactions
    // x: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    // y: "31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904"

    /**
     *  BlindCommit(blind, value) : ECPoint
     *
     *  Returns a Pedersen commitment for blind TX on secp256k1 curve.  This is curve point that
     *  commits to a value.  It is blinded by a random blinding factor.  Blind and value are taken
     *  as BigIntegers assumed less than curve order n.
     *
     *  Computed as: commit = blind * G + value * G2.
     *
     */
    fun BlindCommit(blind: BigInteger, value: BigInteger) : ECPoint {

        return G.multiply(blind).add(G2.multiply(value))

    }

}
