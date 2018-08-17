import org.bouncycastle.jce.interfaces.ECKey

/*{"weight_threshold":1,"account_auths":[],
    "key_auths":[[to_key.child(child),1]],
    "address_auths":[]}*/
data class owner_dat(var weight_treshold: Int,
                 var account_auths: Array<String?>?,
                 var key_auths: Array<ECKey?>,
                 var address_auth: Array<Any?>)
//var amountasset = //<HERE> - Create data class to match:
/*{"amount":amount, "asset_id":this.asset.get("id")};*/
data class amountasset_dat(var amount: Long, var asset_id: String?)
/*Recipients[0] = {"label":this.to.label, "markedlabel":this.to.markedlabel,
                         "amountdue":{"amount":this.amount,
                                      "asset_id":this.asset.get("id")},
                         "pubkey":this.to.pubkey
                        };*/
data class amountdue_dat(var amount: Long, var asset_id: String?)
data class recipient_dat(var label: String?, var markedlabel: String?, var amountdue: amountdue_dat, var pubkey: String)
data class key_auths_dat(var key: String, var Val: Int)
data class outOwner_dat(var weight_treshold: Int,var account_auths: Array<String?>?,var key_auths: Array<key_auths_dat>,var address_auths: Array<Any>)
data class bopInputs_dat(var commitment: Any?, var owner: Any?)
