import jdk.nashorn.internal.objects.NativeUint8Array

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
    var one_time_key: PublicKey? = null
    var to: PublicKey? = null
    var encrypted_memo: Any? = null

    /* This sets the key fields, both should be public keys.
    *
    **/
    fun SetPubKeys(One_Time: PublicKey, To_Key: PublicKey)
    {
        one_time_key = One_Time
        to = To_Key
    }
    /**
     *  Serialize and express as base58 string. //Todo: This is definitely Not finished.
     */
    fun Base58(): String
    {
        return bs58.encode(Serializer.stealth_confirmation.toBuffer() //TODO: Find appropriate b58 module. also java serializer.
    }
    fun ReadBase58(rcpt_txt)
    {
        var tmp = Serializer.stealth_confirmation.fromBuffer(bs58.decode(rcpt_txt))//TODO: Again, appropriate b58 & serializer
        one_time_key = tmp.one_time_key
        to = tmp.to
        encrypted_memo = tmp.encrypted_memo
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
    var from: Any? = null// optional public_key_type
    var amount: Any? = null
    var blinding_factor: String = ""
    var commitment: String = ""
    var check: Boolean = false

    /**
     *  Set all the required fields except the check word. If desired
     *  to set 'from' field, set it explicitly separately.  The check
     *  word should be set last, (typically by ComputeReceipt() in
     *  blind_output_meta object).
     */
    fun Set(amount: Any?, blind: String, comit: String): Unit
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
    fun EncryptWithSecret(seccret: Any?): ByteArray//Todo: Aescoder..
    {
        var aescoder: Any? = Aes.fromSha512(secret.toString("hex"))
        var memo_data_flat: ByteArray = Serializer.stealth_memo_data.toBuffer(this)
        var retval: ByteArray = aescoder.encrypt(memo_data_flat)
        aescoder.clear()
        return retval
    }
    fun Decrypt(encrypted: Any?, secret: ByteArray ): Unit
    {
        var aescoder: AesCoder = Aes.fromSha512(secret.toHex())
        var memo_data_flat: ByteArray = aescoder.decrypt(encrypted) // :o
        var memo = Serializer.stealth_memo_data.fromBuffer(memo_data_flat)
        this.from: String = memo.from
        this.amount: Any? = memo.amount
        this.blinding_factor = memo.blinding_factor
        this.commitment = memo.commitment
        this.check = memo.check
        aescoder.clear()
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
    var pub_key: PublicKey? = null
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
        if(one_time.constructor.name.equals("PrivateKey", true))
        {
            one_time = one_time.toPublicKey() //Drop Private info.
        }
        this.pub_key = to_key
        this.confirmation.SetPubKeys(one_time, to_key)
    }
    /**
     *  Sets the primary fields on the decrypted_memo member. This is
     *  the info that gets encrypted in the receipt. Does not set the
     *  check-word; this gets set later by ComputeReceipt().
     */
    fun SetMemoData(amount: Any?, blind: String, comit: String): Unit
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
        var check32 = (NativeUint8Array(secret.slice(0,4),0,1)[0])
        this.decrypted_memo.check = check32 as Boolean
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
    var consumed_comits: MutableList<String> = mutableListOf()
    var trx = //Todo: Transaction_Builder discussion with team
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
    var comitment: String = ""
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
    var amount: Any? = null
    var from: Any? = null
    var blinding_factor: Any? = null
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
