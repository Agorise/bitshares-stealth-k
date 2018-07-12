import cy.agorise.graphenej.Address
import java.nio.Buffer
import org.bitcoinj.core.ECKey
import cy.agorise.graphenej.PublicKey
import org.bitcoinj.core.DumpedPrivateKey
import java.math.BigInteger

/**
 * A "blind coin" is the information needed to spend a particular blind
 * commitment deposited in the blockchain.
 *
 * RETREIVE and STORE from RECIPT:
 *
 * let pkeyfind = (addr)=>{return "5xxxxx";} // (must return WIF from addr)
 * let bc = BlindCoin.fromReceipt(rcpt_txt, pkeyfind);
 * DB.Stash(bc.toDBObject(),bc.ask_address());
 *
 * The ask_address() method returns the address that was used to request
 * blind funds.  This can be used to associate the coin with the blind
 * account containing the address when storing in the database.  The address
 * itself does not need to be explicitly stored.
 *
 * The toDBObject() method returns a "lightweight" representation of the
 * BlindCoin object for storage/retreival.  There is a corresponding static
 * fromDBOject() to generate a BlindCoin object after DB retreival.
 */
 class BlindCoin(
                var auth_privkey: Any?,
                var value: Any?,
                var asset_id: Any?,
                var blinding_factor: ByteArray,
                var commitment: ByteArray,
                var spent: Buffer,
                var asking_pubkey: Any? = null
){
     /**
     * Generally shouldn't be called directly.  New coin objects should
     * either be generated with fromReceipt() or fromDBObject() (which in
     * turn call this).
                auth_privkey,           // PrivateKey object or WIF; Spend key
                value,                  // Long; Amount in atomic units
                asset_id,               // ID of asset as "1.3.x" or integer x
                blinding_factor,        // Assuming Buffer 32 bytes 
                commitment,             // Assuming Buffer 33 bytes
                spent,                  // true/false
                asking_pubkey = null    // (Optional)
     */
    init
    {
        if(auth_privkey is String)
        {
            var x = auth_privkey
            auth_privkey = PrivateKey.fromWif(x as String)
        }
        if(value is String) //Todo : <Here> Polish this init for tsafety
        {
            var x: String = value as String
            var y: Long = x.toLong()
            value = y }
        if(asset_id !is String)
        {   var x = asset_id as Int
            var y:String = "1.3."+asset_id
            asset_id = y }
        if(asking_pubkey is String)
        {
            var x = asking_pubkey as String
            //var y = PublicKey.fromStringOrThrow(asking_pubkey)
            var y = asking_pubkey
            asking_pubkey = Address(y as String).publicKey.key
        }
    }
    /**
     * Returns the "asking address" which was used to request the funds
     * contained by the coin.  String value, eg, "BTSxxxx..."
     */
    fun ask_address(): String { return asking_pubkey.toString() }
    fun valueString(): String { return value.toString()}
    fun commitmentHex(): String {return commitment.toHex()}
    fun blindingFactorHex(): String{ return blinding_factor.toHex()}
    /**
     * Gets a "blind coin" from a base58-encoded receipt if a private key
     * needed to decode the receipt can be found.  See also fromReceipts()
     * for a version that returns an array from a comma-separated list of
     * receipts.
     *
     * @arg rcpt_txt      - Receipt as base58 text
     * @arg DB            - Stealth DB from which wif can be querried,
     *                      or else explicit wif as string
     *
     * returns: false || new BlindCoin(...)
     *
     * returns false if wallet contains no private key that can decode the
     *         receipt, or else a BlindCoin object if receipt is
     *         successfully decoded.
     *
     * NOTE: This does NOT check whether the commitment is in fact present
     * and unspent in the blockchain, but only returns the info from the
     * receipt.  Checking for spendability should only be done when updating
     * balance displayed to the user and before contructing a blind spend
     * operation in order to avoid unnecessarily revealing our "interest" in
     * the particular commitment to the p2p network.
     */
    fun fromReceipt(receipt_txt: String, DB: Any?) : Unit
    {
        var confirmation = stealth_confirmation()
        confirmation.ReadBase58(receipt_txt)
        var askingwif: Boolean = false;
        if(DB !is String)
        {
            askingwif = DB.PrivKeyFinder(confirmation.to.toString())
        }
    }

 }