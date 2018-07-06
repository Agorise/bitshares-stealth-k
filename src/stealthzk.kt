import org.bouncycastle.math.ec.ECFieldElement
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
import java.math.BigInteger
import java.security.spec.ECField


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
data class secp256k1altgenc(var G2x: String = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", var G2y: String = "31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904")
var secp256k1altgen = secp256k1altgenc()
var G2X = getfieldelement
var G2 = ECPoint(SecP256K1Curve(), ECFieldElement, ECFieldElement)
fun zk_sha256(input): Unit
{
    return BA_Buffer.from(sha256.array(input))
}
class StealthZK{

}