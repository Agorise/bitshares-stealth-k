import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import java.security.KeyPair
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

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
 *  keypair is your address key pair, and the remote is the one-time-key pubkey that should be embedded in the transaction (or included in a transaction receipt).
 *
 *  config:  StealthConfig object specifying curve and value bounds, etc.
 *
 */
class BlindOutput(val config: StealthConfig,
                      val LocalPubKey: ECPublicKey,
                      val LocalPrivKey: ECPrivateKey,
                      val RemotePubKey: ECPublicKey) {


}