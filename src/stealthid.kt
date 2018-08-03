import cy.agorise.graphenej.Address
import cy.agorise.graphenej.PublicKey
import org.bitcoinj.core.ECKey

data class CAccount(val name: String, val id: String)
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
class StealthID(label_or_account: Any, pubkeyobj: Any?, privkeyobject: ECKey?)
{
    /**
     * Don't call directly.  Use the finder functions.
     *
     * @arg label_or_account - if a string, assume stealth account or
     *          contact, and subsequent args will/may be set.  If not string,
     *          then assume a ChainStore Account object for a PUBLIC account.
     */
    var label: Any = false
    var account: Any = false
    var markedlabel: Any = false
    var PublicKey: PublicKey? = null
    var PrivateKey: ECKey? = null
    var isblind: Boolean = false
    lateinit var id: Any;
    lateinit var coins: Array <BlindCoin>;
    init
    {
        if(label_or_account is String)
        {
            label = label_or_account
            markedlabel = "@"+label
            if(PrivateKey != null)
            {
                var xtempk = PrivateKey
                var xtemp =ECKey.fromPublicOnly(xtempk?.pubKey)
                PublicKey = PublicKey(xtemp)
            }
            else{PublicKey = pubkeyobj as PublicKey}
            PrivateKey = privkeyobject //may be null or undefined
            isblind = true
        }
        else if(label_or_account is CAccount)
        {
            account = label_or_account
            var acc = account
            label = (acc as CAccount).name
            markedlabel = label
            id = acc.id
            isblind = false;
        }
        else 
        {
            throw(Exception("Tried to pass something other than a string or a Caccocunt to stealthID class."))
        }
    }

    fun canBlindSpend(): Boolean 
    {
        if(PrivateKey != null)
        {
            return true
        }
        return false
    }
    fun isStealthLabel(labelstring: String): Boolean 
    {
        if(labelstring.get(0).compareTo('@') == 0){return true}
        return false
    }
    fun stripStealthMarker(labelstring: String) : String
    {
        return (labelstring.subSequence(1,labelstring.length).toString())
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
        else if(input is Array<BlindCoin>) {coins = input} //Not done need to fix it it won't work. <HERE>
        else{throw(Exception("Invalid Input: Can only pass a BlindCoin or an array of BlindCoins to setCoins()."))}
     }
     fun findCredentialed(label: String, DB: Any): StealthID
     {
         if(isStealthLabel(label))
         {
            // Find Stealth ACCOUNT by name:
            // TODO Rely on functions already in Database
            var accounts = DB.accounts
            var namelabel = stripStealthMarker(label)
            for( i:Int in accounts.indices)
            {
                if(accounts[i].label.compareTo(namelabel) == 0)
                {
                    var foundID = StealthID(
                        namelabel,
                        ECKey.fromPublicOnly(Address(accounts[i].publickey).pubkey),
                        PrivateKey.fromWIF(accounts[i].privatekey))
                    var coins = DB.GetUnspentCoins(foundID.label)
                    foundID.setCoins(coins)
                    return foundID

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
     fun findAny(label: String, DB: Database): StealthID
     {
         try
         {
             return findCredentialed(label, DB)
         }
         catch(x)
         {
             if(isStealthLabel(label))
             {
                 val contacts = DB.contacts
                 val namelabel = stripStealthMarker(label)
                 for(i in contacts.indices)
                 {
                     if(contacts[i].label.compareTo(namelabel) == 0)
                     {
                         var key = ECKey.fromPublicOnly(Address(contacts[i].publickey as String).publicKey.key.pubKeyPoint)
                         return StealthID(namelabel, key, null)
                     }
                 }
                 throw(Exception("Stealth Contact Not Found"))
             }
         }
     }
}
