import cy.agorise.graphenej.*
import jdk.nashorn.internal.objects.ArrayBufferView
import jdk.nashorn.internal.objects.NativeUint32Array
import jdk.nashorn.internal.objects.NativeUint8Array
import org.bitcoinj.core.ECKey
import org.bitcoinj.core.Base58
import org.bouncycastle.asn1.eac.UnsignedInteger
import org.bouncycastle.math.ec.ECPoint
import org.omg.CORBA.Object
import java.io.ByteArrayOutputStream
import java.io.DataOutput
import java.io.DataOutputStream
import java.io.ObjectOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Charsets
/** confidential.kt
 *
 *  Classes and structs to represent components of confidential
 *  (blind, stealth) transactions on Graphene based chains.
 *
 *  Mostly tranliterated from various bitshares-js
 *
 */


/**
 *  Records the one-time-key, to-key, and memo_data (encrypted) that, upon
 *  being packed and base58 encoded, becomes the TX receipt.
 *
 *  NOTE: The OTK and ToPubKey are NOT encrypted, only the memo_data. Thus,
 *  a receipt, if transmitted insecurely, identifies the Asking Address of
 *  the recipient.  If the receipt can be separately correlated with either
 *  the receiving address or the sender, then a lot of metadata is revealed.
 *
 *  from: confidential.hpp
 *    in: bitshares-core/libraries/chain/include/graphene/chain/protocol/
 */

class stealth_confirmation()
{
    var one_time_key: String? = null
    var to: String? = null
    var encrypted_memo: ByteArray? = null

    /* This sets the key fields, both should be public keys.
    *
    **/
    fun SetPubKeys(One_Time: Address, To_Key: Address)
    {
        one_time_key = One_Time.publicKey.address
        to = To_Key.publicKey.address
    }
    /**
     *  Serialize and express as base58 string. //Todo: This is definitely Not finished.
     */
    fun Serialize() : ByteArray {
        var a = one_time_key?.toByteArray(Charsets.UTF_8)
        if (this.one_time_key != null && to != null && encrypted_memo != null) {
            var a = one_time_key
            var b = to
            var c = encrypted_memo
            var stealth_memo = object {
                val one_time_key = ECKey.fromPublicOnly(ECKey.compressPoint(Address(a as String).publicKey.key.pubKeyPoint))
                val to = ECKey.fromPublicOnly(ECKey.compressPoint(Address(b as String).publicKey.key.pubKeyPoint))
                val encrypted_memo = c as ByteArray
            }
            return byteArrayOf(*stealth_memo.one_time_key.pubKey, *stealth_memo.to.pubKey, *stealth_memo.encrypted_memo)
        }
        return byteArrayOf(0)
    }
    fun Base58(): String
    {
            var x = this.Serialize()
            return Base58.encode(x)
    }
    fun ReadBase58(rcpt_txt: String)
    {
        var tmp = Base58.decode(rcpt_txt)
        /*Todo: Deserialization
        this.one_time_key = tmp.one_time_key
        this.to = tmp.to
        this.encrypted_memo = tmp.encrypted_memo*/
    }

}
/**
 *  Data the recipient needs in order to spend an output that they have
 *  received. (Encrypted form gets stored inside stealth_confirmation.)
 *
 *  from: confidential.hpp (as stealth_confirmation::memo_data)
 *    in: bitshares-core/libraries/chain/include/graphene/chain/protocol/
 */
class stealth_cx_memo_data()
{
    var from: String? = null// optional public_key_type
    var amount: AssetAmount? = null
    var blinding_factor: ByteArray? = null
    var commitment: ByteArray? = null
    var check: ByteArray? = null

    /**
     *  Set all the required fields except the check word. If desired
     *  to set 'from' field, set it explicitly separately.  The check
     *  word should be set last, (typically by ComputeReceipt() in
     *  blind_output_meta object).
     */
    fun Set(amount: AssetAmount?, blind: ByteArray, comit: ByteArray): Unit
    {
        this.amount = amount
        this.blinding_factor = blind
        this.commitment = comit
    }
    /**
     *  Serializes and encrypts memo data, returning as a Buffer.
     *
     *  @param secret is a 512-bit secret as a Buffer object (I
     *         think), used to initialize key and iv of the aes
     *         encoder.
     */
    fun Serialize() : ByteArray
    {
        var ifrom: Any? = null;
        if(this.from != null){ifrom = ECKey.fromPublicOnly(ECKey.compressPoint(Address(this.from as String).publicKey.key.pubKeyPoint))}
        var amount = this.amount as Long
        var blinding = this.blinding_factor as ByteArray
        var commit = this.blinding_factor as ByteArray
        var check = this.check
        var stealth_cx_memo_datax = object  {
            var from = ifrom as ECKey?
            var amount = amount
            var blinding_factor = blinding
            var commitment: ByteArray = commit
            var check = check
        }

        var baos = ByteArrayOutputStream()
        var oos: DataOutput = DataOutputStream(baos)
        Varint.writeUnsignedVarLong(stealth_cx_memo_datax.amount, oos)
        var amtbytes =  baos.toByteArray()
        return byteArrayOf(*(stealth_cx_memo_datax.from as ECKey).pubKey, *amtbytes, *stealth_cx_memo_datax.blinding_factor,*stealth_cx_memo_datax.commitment, *stealth_cx_memo_datax.check as ByteArray)
    }
    fun EncryptWithSecret(secret: ByteArray): ByteArray//Todo: Aescoder..
    {
        if(secret.size < 128) { throw error("Hash(Byte Array, not hex) smaller than 64 passed.") }
        var aiv = secret.slice(IntRange(32,48)).toByteArray()
        var akey = secret.slice(IntRange(0,32)).toByteArray()
        var x = Cipher.getInstance("AES/CBC/PKCS5Padding")
        var y = SecretKeySpec(akey, "AES")
        x.init(Cipher.ENCRYPT_MODE,y,IvParameterSpec(aiv))
        var memo_data_flat: ByteArray = this.Serialize()
        return x.doFinal(memo_data_flat)

    }
    fun Decrypt(encrypted: ByteArray?, secret: ByteArray ): Unit
    {

        if(secret.size < 128) { throw error("Hash(Byte Array, not hex) smaller than 64 passed.") }
        var aiv = secret.slice(IntRange(32,48)).toByteArray()
        var akey = secret.slice(IntRange(0,32)).toByteArray()
        var x = Cipher.getInstance("AES/CBC/PKCS5Padding")
        var y = SecretKeySpec(akey, "AES")
        x.init(Cipher.DECRYPT_MODE,y,IvParameterSpec(aiv))
        var memo_data_flat: ByteArray = x.doFinal(encrypted)
        /*var memo = Serializer.stealth_memo_data.fromBuffer(memo_data_flat) Todo: Deserialization
        this.from = memo.from
        this.amount = memo.amount
        this.blinding_factor = memo.blinding_factor
        this.commitment = memo.commitment
        this.check = memo.check*/
    }
}
/**
 *  Metadata surrounding a blind output, for internal retention/use by
 *  wallet.  (See also blind_output)
 *
 *  Contains the transaction Receipt which the sender must communicate to
 *  the recipient, and metadata to aid correlating receipt to recipient.
 *
 *  from: wallet.hpp (as blind_confirmation::output)
 *    in: bitshares-core/libraries/wallet/include/graphene/wallet/wallet.hpp
 */

class blind_output_meta()
{
    var label:String = ""
    var pub_key: String? = null
    var decrypted_memo = stealth_cx_memo_data()
    var confirmation = stealth_confirmation()
    var auth: Any? = null
    var confirmation_receipt: String = ""
    /**
     *  Sets the one-time and to PubliKeys in the appropriate
     *  locations in this struct and its member structs.  Both
     *  parameters should be PublicKeys but we tolerate if one_time is
     *  sent as PrivateKey.
     */
    fun SetKeys(one_time: Any?, to_key: Any?) : Unit
    {
        var x: Any? = null
        if(one_time is PrivateKey.Companion)
        {
            x = Address(ECKey.fromPublicOnly(one_time.key.pubKey))
            this.pub_key = to_key as String
            this.confirmation.SetPubKeys(x, to_key as Address)

        }
        else
        {
            this.pub_key = to_key as String
            this.confirmation.SetPubKeys(Address(one_time as String), to_key as Address)
        }
    }
    /**
     *  Sets the primary fields on the decrypted_memo member. This is
     *  the info that gets encrypted in the receipt. Does not set the
     *  check-word; this gets set later by ComputeReceipt().
     */
    fun SetMemoData(amount: AssetAmount, blind: ByteArray, comit: ByteArray): Unit
    {
        this.decrypted_memo.Set(amount, blind, comit)
    }
    /**
     *  Using @a secret, we complete the memo data with a check word,
     *  then encrypt the memo data, then base58 the confirmation
     *  struct to compute confirmation_receipt.
     */
    fun ComputeReceipt(secret: ByteArray): Unit
    {
        var check32 = secret.slice(IntRange(0,4)).toByteArray()
        this.decrypted_memo.check = check32
        this.confirmation.encrypted_memo = this.decrypted_memo.EncryptWithSecret(secret)
        this.confirmation_receipt = this.confirmation.Base58()
    }
}
/**
 *  Contains the final signed transaction and a vector of output metadata,
 *  including the "receipt" that the sender must give the receiver.
 *
 *  from: wallet.hpp
 *    in: bitshares-core/libraries/wallet/include/graphene/wallet/wallet.hpp
 */
class blind_confirmation()
{
    var output_meta: MutableList<blind_output_meta> = mutableListOf()
    var consumed_commits: MutableList<String> = mutableListOf()
    //var trx = //Todo: Transaction_Builder discussion with team
}
/**
 *  Represents a blind output (somewhat like a Bitcoin UTXO).  A blind
 *  transaction will contain one or more of these blind outputs.
 *
 *  On the p2p network, outputs are indexed by the commitment
 *  data and are retrievable with API call
 *  database_api::get_blinded_balances(confirmation)
 *
 *  from: confidential.hpp
 *    in: bitshares-core/libraries/chain/include/graphene/chain/protocol/
 */
class blind_output()
{
    var commitment: String = ""
    var range_proof: String = ""
    var owner: Any? = null
    var stealth_memo = stealth_confirmation()
}
/**
 *  Represents a transfer_to_blind operation (Op-code 39), suitable be
 *  included in a transaction for broadcast.
 *
 *  from: confidential.hpp
 *    in: bitshares-core/libraries/chain/include/graphene/chain/protocol/
 */
class blind_input()
{
    var comitment = ByteArray(33)
    var owner: MutableList<String> = mutableListOf()
}
class transfer_to_blind_op()
{
    var fee: Any? = null
    var amount: AssetAmount? = null
    var from: Int? = null
    var blinding_factor: ByteArray? = null
    var outputs: MutableList<blind_output> = mutableListOf()
    //fee_payer() {/* return this.from; */}
    //validate(){} //TODO Chris's todo
    //calculate_fee(/*TODO*/){/*TODO*/} // returns share_type  chris's todo
}
class blind_transfer_op()
{
    var fee: Any? = null
    var inputs: MutableList<blind_input> = mutableListOf()
    var ouputs: MutableList<blind_output> = mutableListOf()
}

class blind_memo()
{
    var from: String = ""
    var amount: Int = 0
    var message: String = ""
    var check: Boolean = false
}
class transfer_from_blind_op()
{
    var fee: Any? = null
    var amount: Any? = null
    var to: Any? = null
    var blinding_factor: Any? = null
    var inputs: MutableList<blind_input> = mutableListOf()
    //fee_payer() {/* return this.from; */}
    //validate(){} //TODO Chris's todo
    //calculate_fee(/*TODO*/){/*TODO*/} // returns share_type  chris's todo
}
