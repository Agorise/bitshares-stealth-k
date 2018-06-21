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

 class BlindCoin(auth_privkey,
                value,                  
                asset_id,               
                blinding_factor,         
                commitment,             
                spent,                  
                asking_pubkey = null    
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
    lateinit var auth_privkey: Any?
    init
    {
        if(auth_privkey is String)
        {auth_privkey=PrivateKey.fromWif(auth_privkey)}
        else{auth_privkey=auth_privkey}
        if(value is String)
        {value = }
        else{}
    }

 }