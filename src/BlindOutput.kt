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
import java.security.PublicKey
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
 */
class BlindOutput(val config: StealthConfig,
                      val LocalKeyPair: KeyPair,
                      val RemotePubKey: PublicKey) {

    var sharedPoint : ECPoint? = null


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
    fun ComputeSharedSecret() : Int {

        val ka = KeyAgreement.getInstance("ECDH", "BC")
        ka.init(this.LocalKeyPair.private)
        ka.doPhase(this.RemotePubKey, true)
        val sharedXbuf = ka.generateSecret()

        // TODO: Confirm that buffer length of sharedXbuf mathches that of the curve's prime field.
        // (in other words, same length as an encoded X coord. This is to ensure hashed value matches
        // reference wallet.)

        println("SharedXBuf: ${Hex.toHexString(sharedXbuf)}")


        return 0
    }
}