data class Privkeyobject(val key: String)//todo
data class Pubkeyobj(val key: String) //todo
data class CAccount(val key: String) //todo
/**
 *  This class is a wrapper class around account/contact classes of
 *  heterogeneous type. It provides uniform access no matter if we are
 *  wrapping a REGULAR account, or a STEALTH ACCOUNT (for which we have a
 *  private key) or a CONTACT (for which we do NOT have a private key).
 *
 *  Provides two finder functions that search either in ChainStore (for
 *  regular accounts) or in Stealth_DB for account labels marked with an
 *  "@".  The two finder functions differentiate on whether we are looking
 *  for a CREDENTIALED account (one we can spend FROM) or ANY
 *  account/contact (one we can spend TO).
 */
class StealthID(label_or_account: Any, pubkeyobj: Any?, privkeyobject: Any?)
{
    /**
     * Don't call directly.  Use the finder functions.
     *
     * @arg label_or_account - if a string, assume stealth account or
     *          contact, and subsequent args will/may be set.  If not string,
     *          then assume a ChainStore Account object for a PUBLIC account.
     */
    constr
    var label: Any = false;
    var account: Any = false;
    var markedlabel: Any = false;
    lateinit var pubkey: Any?;
    lateinit var privkey: Any?;
    var isblind: Boolean = false;
    lateinit var id: Any;
    lateinit var coins: Array <BlindCoin>;
    init
    {
        if(label_or_account is String)
        {
            label = label_or_account
            markedlabel = "@"+label
            if(privkey != null){ pubkey = privkey.toPublicKey()}
            else{pubkey = pubkeyobj}
            privkey = privkeyobj //may be null or undefined
            isblind = true
        }
        else if(label_or_account is CAccount)
        {
            account = label_or_account
            label = account.get("name")
            markedlabel = label
            id = account.get("id")
            isblind = false;
        }
        else 
        {
            throw(Exception("Tried to pass something other than a string or a Caccocunt to stealthID class."))
        }
    }

    fun canBlindSpend(): Boolean 
    {
        if(privkey != null)
        {
            return true
        }
        return false
    }
    fun isStealthLabel(labelstring: String): Boolean 
    {
        return (labelstring.get(0).compareTo('@'))
    }
    fun stripStealthMarker(labelstring: String) : String
    {
        return (labelstring.subsequence(1,labelstring.length))
    }
    /**
     * Sets the list of BlindCoin's for a StealthID.  Input can be a
     * single coin object or an array of coin objects.  Coin objects may
     * be in fully-constructed "heavy" form, or the lighweight form used
     * for database storage/retreival.
     */
     fun setCoins(input: Any)
     {
        if(input is BlindCoin){coins = arrayOf(input)}
        else if(input is Array <BlindCoin>) {coins = input} //Not done need to fix it it won't work. <HERE>
        else{throw(Exception("Invalid Input: Can only pass a BlindCoin or an array of BlindCoins to setCoins()."))}
     }
     fun findCredentialed(label: String, DB: Any): StealthID
     {
         if(StealthID.isStealthLabel(Label: String))
         {
            // Find Stealth ACCOUNT by name:
            // TODO Rely on functions already in Database
            var accounts = DB.accounts
            var namelabel = StealthID.StripStealthMarker(label)
            for(for i:Int in accounts.indices)
            {
                if(accounts[i].label.compareTo(namelabel) == 0)
                {
                    var foundID = new StealthID(
                        namelabel,
                        PublicKey.fromStringOrThrow(accounts[i].publickey)
                        PrivateKey.fromWIF(accounts[i].privatekey)
                    var coins = DB.GetUnspentCoins(foundID.label)
                    foundID.setCoins(coins)
                    return foundID
                    )
                }
            }
            throw(Exception("Couldn't find $namelabel in stealth accounts."))
         }
         else
         {
             //Find Regular account from MY accounts
             var accounts = DB.getRegularAccounts();
             for(i in accounts.indices)
             {
                 if(accounts[i].compareTo(label) == 0)
                 {
                     return StealthID(DB.getRegularAccWithName(label), null , null) //Investigation required
                 }
             }
             throw(Exception("Could not find name in regular accounts!"))
         }
     }
     fun findAny(label: String, DB): StealthID
     {
         try
         {
             return StealthID.findCredentialed(label, DB)
         }
         catch
         {
             if(StealthID.isStealthLabel(label))
             {
                 val contacts = DB.contacts
                 val namelabel = StealthID.stripStealthMarker(label)
                 for(i in contacts.indices)
                 {
                     if(contacts[i].label.compareTo(namelabel) == 0)
                     {
                         return StealthID(namelabel, PublicKey.fromStringOrThrow(contacts[i].publickey))
                     }
                 }
                 throw(Exception("Stealth Contact Not Found"))
             }
         }
     }
}
