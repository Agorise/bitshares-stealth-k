import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.util.encoders.Hex
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
class BlindOutput(val config: StealthConfig,
                  val onetimePub: PublicKey,
                  val addressPub: PublicKey,
                  val privateKey: PrivateKey,
                  val isReceiver: Boolean      // True implies private corresponds to addressPub, else onetimePub
                 )
{

    val localPubKey : PublicKey    // return the PubKey for which we know the private key
        get() = if(isReceiver) addressPub else onetimePub

    val remotePubKey : PublicKey   // return PubKey for which we DON'T know the private key
        get() = if(isReceiver) onetimePub else addressPub


    /**
     *  Compute Shared Secret Data between local and remote keys.
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
    fun ComputeSharedSecret() : ByteArray {

        val ka = KeyAgreement.getInstance("ECDH", "BC")
        ka.init(this.privateKey)
        ka.doPhase(this.remotePubKey, true)
        val sharedXbuf = ka.generateSecret()   // Byte[n] array; n matches size of key filed (32 for secp256k1)

        val digest512 = MessageDigest.getInstance("SHA-512")
        digest512.reset()
        val shareddata = digest512.digest(sharedXbuf)  // Byte[64] array

        println("SharedXBuf: ${Hex.toHexString(sharedXbuf)}")
        println("SharedData: ${Hex.toHexString(shareddata)}")

        return shareddata

    }

    /** Compute the Public Key authorized to SPEND the output.
     *
     *  This key is derived in a deterministic way from the ECDH shared secret between sender-generated Random Key
     *  and receiver's Address Key(s).  Specifically, a child-key offset from the receiver's public key is computed.
     */
    fun ComputeSpendPubkey() : PublicKey {

        val shareddata = this.ComputeSharedSecret()
        val digest256 = MessageDigest.getInstance("SHA-256")
        val offset = digest256.digest(shareddata)

        /** Note: The offsetting process in the cli_wallet is bizarrely complex, and doesn't seem (at first glance)
         *  to be a simple additive offset process.  Perhaps it's attempting to mimic XPRIV/XPUB child key process,
         *  but using something on-the-fly as the chain code???  Not sure.  Anyway, references:
         *
         *  public_key::child(offset) is called from wallet.cpp in:
         *  https://github.com/bitshares/bitshares-core/blob/58969c2a0307e32bbdee731d1f3f9a193b0d1b3f/libraries/wallet/wallet.cpp#L4264
         *
         *  fc::ecc::public_key::child()
         *  fc::ecc::private_key::child()  are defined in:
         *  https://github.com/bitshares/bitshares-fc/blob/master/src/crypto/elliptic_common.cpp
         *  https://github.com/bitshares/bitshares-fc/blob/master/include/fc/crypto/elliptic.hpp
         *
         *  fc::ecc::public_key::add()  is defined in:
         *  https://github.com/bitshares/bitshares-fc/blob/master/src/crypto/elliptic_secp256k1.cpp
         *  Ack!  It's also defined in at least one other file in that directory.
         *  Choice of implementation perhaps? (ssl vs secp256k1-zkp?)
         *
         *  UPDATE: It LOOKS like public_key::add() for a pubkey A = aG and offsetprime c results in
         *  a key P = aG + cG.  My eyes were bleeding traversing the source tree (also ended up in secp256k1-zkp
         *  repo).  But it DOES look like a linear add to receiver's Address key.  Surprising thing is (it looks
         *  so far, anyway) that the "offset" arg to the child() function does NOT become the value c that
         *  multiplies G, but rather c = sha256(A|offset).  ...So there's another hash round. (Perhaps in parallel
         *  to XPUB protocol)
         *
         *  AND:  Looking at PublicKey in JavaScript bitsharesjs pretty much confirms this is the derivation
         *  procedure.  (God, that code is much easier to follow...)
         *  https://github.com/bitshares/bitsharesjs/blob/master/lib/ecc/src/PublicKey.js
         *
         */

        return this.config.generateKeyPair().public  // TEMP: (Obviously)

    }
}