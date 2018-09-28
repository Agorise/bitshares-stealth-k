import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.util.encoders.Hex
import sun.jvm.hotspot.runtime.Bytes
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PublicKey
import java.security.PrivateKey
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement



/**
 *  Class BlindOutput
 *
 *  Encodes an output of a Confidential Transactions (or similar) "Stealth" transaction.  Includes helper
 *  functions for recognizing outputs as one's own, and for computing commitment randomness and offset
 *  addresses in a deterministic way (thereby reducing needed communication between sender and recipient).
 *
 *  This class can be used both to create outputs (e.g. when constructing a transaction) and to interpret
 *  outputs (e.g. when receiving a transaction).
 *
 *  To generate deterministic parameters, both a "local" key pair and a "remote" public key are used.
 *  The local key assumed to be a key pair (a public and private pair), and the remote is only a public.
 *  If you are the sender, then the local keypair is the one-time-key that you have generated randomly,
 *  and the remote is the receiver's stealth-address public key.  If you are the receiver, the the local
 *  keypair is your address key pair, and the remote is the one-time-key pubkey that should be embedded
 *  in the transaction (or included in a transaction receipt).
 *
 *  config:  StealthConfig object specifying curve and value bounds, etc.  (Shouldn't be needed since keys contain curve specs)
 *
 *  TODO: Note: we can't quite use "local" and "remote" nomenclature for the keys, because there IS an assymetry:
 *  The receiver can comput PRIVATE key for child PubKey, but the sender cannot.  So it matter whether we are the
 *  person who knows the private key for the randomness or the private key for the stealth address. To make this
 *  class sender/receiver agnositic, we need to take keypairs for BOTH sender and receiver, but requiring ONE of
 *  the private keys to be null (or nonsense).  What we can do depends on which private key we have.
 *  (OR the sig could be senderPubKey, receiverPubKey, privateKey, privKeyIsRcvr : bool)
 *
 */
const val SHARED_SECRET__HASH_LENGTH = 64
class BlindOutput(val config: StealthConfig,
                  val onetimePub: PublicKey,
                  val addressPub: PublicKey,
                  val privateKey: PrivateKey,
                  val isReceiver: Boolean      // True implies private corresponds to addressPub, else onetimePub
                 )
{

    /*** STATE PROPERTIES ***/

    val sharedsecret : ByteArray               /** 512-bit secret shared between sender and receiver */
        get() {
            if (_sharedsecret.size != SHARED_SECRET__HASH_LENGTH) {
                _sharedsecret = ComputeSharedSecretHashed() }
            return _sharedsecret }
    private var _sharedsecret = ByteArray(0)   //  valid when .size == SHARED_SECRET_HASH_LENGTH

    val outputPublicKey : PublicKey
        get() {
            if (_outputPublicKey == this.addressPub) {
                _outputPublicKey = ComputeTxOutputPublicKey()
            }
            return _outputPublicKey
        }
    private var _outputPublicKey : PublicKey = addressPub  // valid when != addressPub


    /*** CONVENIENCE ACCESSORS ***/

    val localPubKey : PublicKey    // return the PubKey for which we know the private key
        get() = if(isReceiver) addressPub else onetimePub

    val remotePubKey : PublicKey   // return PubKey for which we DON'T know the private key
        get() = if(isReceiver) onetimePub else addressPub

    private val addressECPoint = (addressPub as BCECPublicKey).q


    /*** PRIVATE HELPER/WORK FUNCTIONS: ***/

    /**
     *  Compute Shared Secret Data between local and remote keys. (Private)
     *
     *  We follow the protocol of the reference wallet (cli_wallet) and take a sha512 hash of the compressed
     *  pubkey representation, with sign byte removed, of the shared EC point.  Removing the sign byte gives
     *  a binary representation of the X-coordinate in isolation in a predictable format (32 bytes for
     *  secp256k1).  Standard ECDH treats only the X-coordinate as the shared secret, so removing the sign
     *  byte makes sense here.
     *
     *  Things which may differ between wallet implementations.  (I have chosen to stay consistent with
     *  reference wallet to reinforce it as a standard.  Without this consistency, recognition of owned
     *  outputs is threatened, since this shared data is used to compute the transaction key as a child of
     *  the stealth address key.)
     *
     *  o) The shared secret.
     *       (We use only the x-coordinate)
     *  o) Representation of x-coordinate.
     *       (We use "compressed" format but excluding leading byte, since that depends on y-coordinate)
     *  o) Hashing algorithm.
     *       (We use sha512)
     *
     */
    private fun ComputeSharedSecretHashed() : ByteArray {

        val ka = KeyAgreement.getInstance("ECDH", "BC")
        ka.init(this.privateKey)
        ka.doPhase(this.remotePubKey, true)
        val sharedXbuf = ka.generateSecret()   // Byte[n] array; n matches size of key filed (32 for secp256k1)

        val digest512 = MessageDigest.getInstance("SHA-512")
        digest512.reset()
        val shareddata = digest512.digest(sharedXbuf)  // Byte[64] array

        println("  Shared X point was: ${Hex.toHexString(sharedXbuf)}")

        return shareddata

    }

    /** Compute the Public Key authorized to SPEND the output.
     *
     *  This key is derived in a deterministic way from the ECDH shared secret between sender-generated Random Key
     *  and receiver's Address Key(s).  Specifically, a child-key offset from the receiver's public key is computed.
     */
    private fun ComputeTxOutputPublicKey() : PublicKey {
        val cG = this.config.G.multiply(ComputeTxOutputPrivKeyDelta())
        val TxOutputQ = this.addressECPoint.add(cG)
        return config.PublicKeyFromECPoint(TxOutputQ)
    }

    /** Compute the scalar offset between Address base-point and the curve point that can SPEND the output
     *
     *  Note: Both sender and receiver can compute this vale.  (But only receiver can compute the actual
     *  key.)  We use the shared-secret data and destination stealth address key to compute scalar offset,
     *  as follows:
     *
     *  offset 'c' = BigInteger(SHA256( [compressed address pubkey] || SHA256([shared secret data]) ))
     *
     *  This agrees with the procedure in cli_wallet, and in bitsharesjs/lib/ecc/src/PublicKey.js
     *
     *  The standardization of this derivation process is necessary to the recipients ability to detect
     *  inbound output due to the relationship between OTK, AddressKey and TxOutputKey.
     */
    private fun ComputeTxOutputPrivKeyDelta() : BigInteger {

        fun _ChildSeedFromSecret(secretdata: ByteArray): ByteArray {
            val digest256 = MessageDigest.getInstance("SHA-256")
            return digest256.digest(secretdata)
        }

        fun _GetPseudoChainCodeFromPublicKeyQ(Q: ECPoint): ByteArray {
            val QEnc = Q.getEncoded(true)
            check(QEnc.size == 33) { "Problem encoding pseudo chain code for child key derivation" }
            return QEnc
        }

        fun _ChildOffsetFromSeed(chain: ByteArray, seed: ByteArray): BigInteger {
            val digest256 = MessageDigest.getInstance("SHA-256")
            digest256.update(chain)
            digest256.update(seed)
            return BigInteger(digest256.digest()) //TODO: bounds check on BigInt
        }

        val childseed = _ChildSeedFromSecret(this.sharedsecret)
        val childchain = _GetPseudoChainCodeFromPublicKeyQ(this.addressECPoint)
        val childoffset = _ChildOffsetFromSeed(childchain, childseed)
        // TODO: Bounds checks on childoffset BigInt

        return childoffset

    }

}