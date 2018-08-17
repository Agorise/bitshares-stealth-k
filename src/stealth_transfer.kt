/**<Here>-Restructure after classes are done. (Shouldn't be with lateinit.)
 *  Wraps up a stealth transfer in a convenient class.
 */
import com.google.common.primitives.UnsignedLong
import com.google.gson.Gson
import cy.agorise.graphenej.*
import cy.agorise.graphenej.operations.CustomOperation
import cy.agorise.graphenej.test.NaiveSSLContext
import jdk.nashorn.internal.objects.NativeUint8Array
import org.bitcoinj.core.ECKey
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.tls.HashAlgorithm.sha256
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import java.security.MessageDigest
import javax.crypto.KeyAgreement
import javax.net.ssl.SSLContext

class Stealth_Transfer(FromID, fromSender: UserAccount,ToID,asset: String,amount: Long,transaction_type: Int)
{
    var from: StealthID = FromID   // StealthID objects
    var to: StealthID = ToID     // ''
    var asset: String = asset         //object, use get("id") to get 1.3.0
    var x = AssetAmount(UnsignedLong.valueOf(900),Asset(asset))
    var amount: Long = amount      // in base units (ie 1.0 BTS = 100000)
    var transaction_type: Int = transaction_type
    var fees: BlindFees? = null //Todo, Blindfees!!!! <HERE>
    var sender = fromSender
    fun Public_to_Blind(): Unit 
    {
        println("Public to blind from ${from.label}, to ${to.markedlabel}")
        var bop = transfer_to_blind_op()
        var blindconf = blind_confirmation()
        //blindconf(aparently never used)
        var total_amount: Long = 0;
        //Loop over recepients (right now only support one.)
        var one_time_key = ECKey()//key.get_random_key() // <HERE> - will need to mimic this somehow.
        var to_key = to.PublicKey//to.pubkey;
        var secret = from.PublicKey?.key?.pubKeyPoint?.multiply(from.PrivateKey?.privKey)?.normalize()?.xCoord?.encoded
        var child = MessageDigest.getInstance("SHA-256").digest(secret) // 256-bit pub/priv key offset <HERE> another mimic
        var nonce = one_time_key.privKey.toByteArray() //256-its (d in Q=d*G)
        var blind_factor = MessageDigest.getInstance("SHA-256").digest(child)
        var amount = amount
        var amountasset = amountasset_dat(amount, null)
        total_amount += amount
        var blinding_factors = arrayOf(blind_factor)
        var Sout = blind_output()
        Sout.owner = owner_dat(1,null,arrayOf(to_key.child(child)),null)
        Sout.commitment = StealthZK.BlindCommit(blind_factor, amount) // <HERE> - Translate stealthZK
        Sout.range_proof = ""// Todo: Requires zk analysis
        var meta = blind_output_meta(); //Metadata for each output, to be kept in blindconf for our history/records.
        meta.label = to.label as String;
        meta.SetKeys(one_time_key, to_key)
        meta.SetMemoData(amountasset, blind_factor, Sout.commitment)
        meta.ComputeReceipt(secret as ByteArray)
        Sout.stealth_memo = meta.confirmation //Omit? Serializer barfs
        blindconf.output_meta = mutableListOf(meta)
        bop.outputs = mutableListOf(Sout)
        println("Receipt: ${meta.confirmation_receipt}")
        bop.from = from.id
        bop.amount = total_amount
        bop.blinding_factor = blind_factor// should be blind_sum but only one
        //Leftover from JS todo: bop.outputs needs to be sorted (if > 1 )
        var uaxs: MutableList<UserAccount> = mutableListOf(sender)
        var tr = CustomOperation(amount, sender, 39, uaxs, Gson().toJson(bop))

    }


    /*
     *  Blind to Blind transfer.
     *
     *  If @to_temp_acct==true, then "to" authority is anonymous, and
     *  we don't .process_transaction().  This is because a second
     *  operation still needs to be added to the TX to "claim" the
     *  temp balance to a public account.  See Blind_to_Public().
     *
     *  TEMP CODE: At present, we spend ENTIRE receipt to single
     *  output.  This will be fixed when we have range proofs.*/

    fun Blind_to_Blind(to_temp_acct: Boolean): Unit 
    {
        var bop: blind_transfer_op = blind_transfer_op()
        var blindconf: blind_confirmation = blind_confirmation()
        var feebase: Any? = (fees!!.blindfees)[0]
        var feeperinput: Any? = (fees!!.blindfees)[1]
        var feeperoutput: Any? = (fees!!.blindfees)[2]

        var CoinsIn: Array<BlindCoin> = BlindCoin.getCoinsSatisfyingAmount(
            from.coins, 
            (amount + feebase as Int),
            feeperinput, 
            feeperoutput)
        var totalfee = feebase as Long + feeperoutput as Long + feeperinput as Long * CoinsIn.size
        var changeamount = BlindCoin.valueSum(CoinsIn.size - this.amount - totalfee)
        var changeoutputneeded = false
        if(changeamount > 0)
        {
            totalfee += feeperoutput
            changeamount =- feeperoutput
            changeoutputneeded = true
        }
        assert(CoinsIn.isNotEmpty() && changeamount >= 0)
        {"Insuficient spendable coins: ${(amount + totalfee)} needed "
          "${BlindCoin.valueSum(from.coins)} available"
          "${BlindCoin.valueSum(CoinsIn)} selected for use."
        }
        for(i in 0 until CoinsIn.size) {
            blindconf.consumed_commits.add(CoinsIn[i].commitmentHex())
        }
        var feeamountasset = amountasset_dat(totalfee, asset.get("id"))
        bop.fee = feeamountasset
        println("Tx amount: ${amount} Change back: ${changeamount} Fee: ${totalfee}")
        var Recipients : MutableList<recipient_dat> = mutableListOf(recipient_dat(to.label, to.markedlabel,amountdue_dat(amount,asset.get.id),to.pubkey))
        if(changeoutputneeded)
        {
            Recipients.add(recipient_dat(to.label, to.markedlabel, amountdue_dat(amount,asset.get("id"))), to.pubkey)
        }
        var blind_factors_in : MutableList<String> = mutableListOf()
        var blind_factors_out = mutableListOf<String>()
        var inputs = BlindCoin.getBlindInputsFromCoins(CoinsIn)
        bop.inputs = inputs;
        for(i in 0 until Recipients.size)
        {
            var needrangeproof = (Recipients.size > 1)
            var needblindsum = (i == Recipients.size-1)
            var Recipient = Recipients[i]

            var one_time_key = ECKey()
            var to_key = Address(Recipient.pubkey).publicKey
            var secret: ByteArray = to_key.key.pubKeyPoint.multiply(one_time_key.privKey).normalize().xCoord.encoded
            //^^var secret = one_time_key.get_shared_secret(to_key);  // 512-bits
            var child = MessageDigest.getInstance("SHA-256").digest(secret)        // 256-bit pub/priv key offset
            var nonce = one_time_key.privKey    // 256-bits, (d in Q=d*G)
            var blind_factor = MessageDigest.getInstance("SHA-256").digest(child)  // (unless blindsum needed)
            if (needblindsum) 
            {
                blind_factor = StealthZK.BlindSum(blind_factors_in,
                                                  blind_factors_out);
            } else {
                blind_factors_out.add(blind_factor)
            }
            var amount = Recipient.amountdue.amount
            var amountasset = amountasset_dat(amount, asset.get("id"))
            println("Output ${1+i} of ${Recipients.size}")
            println(" to ${Recipient.markedlabel}")
            println("Amount = ${amount}")
            var sout = blind_output()             // One output per recipient
            var nullowner: Boolean = to_temp_acct && (i===0)// To be claimed in op 41
            if(nullowner)
            {
                sout.owner = outOwner_dat(0, emptyArray<String?>(), emptyArray<key_auths_dat>(), emptyArray<Any>())
            }
            else
            {
                sout.owner = outOwner_dat(1, emptyArray<String?>(), arrayOf(key_auths_dat(to_key.child(child), 1)), emptyArray<Any>())
            }

            sout.commitment = StealthZK.BlindCommit(blind_factor,amount)
            if(needrangeproof){sout.range_proof = RangeProof.SignValue(amount,blind_factor, nonce)}
            else{sout.range_proof = emptyArray<Int>()}
            var meta = blind_output_meta()
            meta.label = Recipient.label
            meta.auth = sout.owner
            meta.SetMemoData(amountasset, blind_factor, sout.commitment);
            meta.ComputeReceipt(secret);            // secret used as AES key/iv
            sout.stealth_memo = meta.confirmation;   // Omit??? (Serializer spits)
            blindconf.output_meta.add(meta);
            bop.outputs.add(sout);
        } //End loop over recipients

        println("Tentative Receipts: (TX not yet broadcast: )")
        for(i in blindconf.outputmeta.indices)
        {
            println("Receipt ${i}:(${blindconf.output_meta[i].label}): ${blindconf.output_meta[i].confirmation_receipt}")
        }
        println("Preparing Transaction for broadcast...")
        //let tr = new TransactionBuilder Delayed till discussion. <HERE>
    }
    /* 
    * From Blind to Public
    */
    fun Blind_To_Public(): Unit
    {
        var feebase = fees!!.unblind[0]
        var whoto = to
        to = from
        amount += feebase
        var stage1 = Blind_to_Blind(true)
        to = whoto
        println("B2PUB: Stage 1 was ${stage1}")
        var bop = transfer_to_blind_op()
        var feeamount = feebase;
        var feeamountasset = amountasset_dat(feeamount, asset.get("id"))
        bop.fee = feeamountasset;
        var input_memo = stage1.output_meta[0].decrypted_memo
        var input_auth = stage1.output_meta[0].auth
        //^^ Need to search rather than assume position zero.
        var amount = input_memo.amount.amount - feeamount
        var amountasset = amountasset_dat(amount, asset.get("id"))
        bop.amount = amountasset;
        bop.to = to.id
        bop.blinding_factor = input_memo.blinding_factor
        bop.inputs = arrayOf(bopInputs_dat(input_memo.commitment, input_auth))
        println("BOP: ${bop}")
        //<HERE> - Transaction builder etc. discuss with team.
    }
}
