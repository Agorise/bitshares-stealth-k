/**<Here>-Restructure after classes are done. (Shouldn't be with lateinit.)
 *  Wraps up a stealth transfer in a convenient class.
 */
class Stealth_Transfer(FromID,ToID,asset,amount,transaction_type)
{
    lateinit var from: StealthID?   // StealthID objects
    lateinit var to: String         // ''
    lateinit var asset: Any?        //object, use get("id") to get 1.3.0
    lateinit var amount: Int        // in base units (ie 1.0 BTS = 100000)
    lateinit var transaction_type: Int
    lateinit var fees: Any? //Todo, Blindfees!!!! <HERE>
    init
    {
        from= FromID
        to=ToID
        asset=asset
        amount=amount
        transaction_type=transaction_type
    }
    fun Public_to_Blind(): Unit 
    {
        println("Public to blind from ${from.label}, to ${to.markedlabel}")
        var bop = transfer_to_blind_op()
        var blindconf = blind_confirmation()
        //blindconf(aparently never used)
        var total_amount = 0;
        //Loop over recepients (right now only support one.)
        var one_time_key = key.get_random_key() // <HERE> - will need to mimic this somehow.
        var to_key = to.pubkey;
        var secret = one_time_key.get_shared_secret(to_key) //512-bits
        var child = hash.sha256(secret) // 256-bit pub/priv key offset <HERE> another mimic
        var nonce = one_time_key.toBuffer() //256-its (d in Q=d*G)
        var blind_factor = hash.sha256(child)
        var amount = amount
        //var amountasset = //<HERE> - Create data class to match:
        /*{"amount":amount, "asset_id":this.asset.get("id")};*/
        total_amount += amount
        blinding_factors = arrayOf(blind_factor)
        var Sout = blind_output()
        //out.owner = //<HERE> - Create data class to match:
        /*
        {"weight_threshold":1,"account_auths":[],
                     "key_auths":[[to_key.child(child),1]],
                     "address_auths":[]}
        */
        Sout.commitment = StealthZK.BlindCommit(blind_factor, amount) // <HERE> - Translate stealthZK
        Sout.range_proof = Uint8Array(0) <HERE> //Perhaps will fail in kotlin.
        var meta = blind_output_meta(); //Metadata for each output, to be kept in blindconf for our history/records.
        meta.label = to.label;
        meta.SetKeys(one_time_key, to_key)
        meta.SetMemoData(ammountasset, blind_factor, Sout.commitment)
        meta.ComputeReceipt(secret)
        Sout.stealth_memo = meta.confirmation //Omit? Serializer barfs
        blindconf.output_meta = arrayof(meta)
        bop.outputs = arrayOf(out)
        println("Receipt: ${meta.confirmation_receipt}")
        bop.from = from.id
        bop.amount = total_amount
        bop.blinding_factor = blind_factor// should be blind_sum but only one
        //Leftover from JS todo: bop.outputs needs to be sorted (if > 1 )
        var tr = TransactionBuilder() // <HERE> This, or an alternative should exist in graphenej.
        //Data classes or similar must be created for this since kotlin can't use undeclared objects.
        //Sending/Broadcasting and registering changes must also be discussed with the crystal team.
        /*Code to be discussed:
        let tr = new TransactionBuilder();
        tr.add_type_operation("transfer_to_blind",{
            fee: {
                amount: 0,
                asset_id: "1.3.0"
            },
            amount: {
                amount: bop.amount,
                asset_id: this.asset.get("id")
            },
            from: bop.from,
            blinding_factor: bop.blinding_factor,
            outputs: bop.outputs
        });
        if (false) { // TESING SHUNT BLOCK
            // Trying to manually generate TX so I can manually broadcast...
            // The ones I manually generate tho always fail with "Missing
            // Active Authority"
            return Promise.all([tr.set_required_fees(),tr.finalize()]).then(()=>{
                /*** console.log ("Try'n catch a TX by the tail yo.");
                /*** console.log(tr.expiration);
                tr.expiration+=600;
                /*** console.log(tr.expiration);
                tr.add_signer(PrivateKey        // Try manually adding signing keys
                   .fromWif("5H***"));
                tr.sign();//
                blindconf.trx = tr;
                /*** console.log(JSON.stringify(tr.serialize()));
                return blindconf;});
        }//END SHUNT - Normal behavior follows...
        return WalletDb.process_transaction(tr,null,true)
            .then(()=>{blindconf.trx = tr; return blindconf;})
            .catch((err)=>{
                return new Error("To_Stealth: WalletDb.process_transaction error: ",
                                 JSON.stringify(err));
            });
    }
        */
    }


    /**
     *  Blind to Blind transfer.
     *
     *  If @to_temp_acct==true, then "to" authority is anonymous, and
     *  we don't .process_transaction().  This is because a second
     *  operation still needs to be added to the TX to "claim" the
     *  temp balance to a public account.  See Blind_to_Public().
     *
     *  TEMP CODE: At present, we spend ENTIRE receipt to single
     *  output.  This will be fixed when we have range proofs.
     */
    fun Blind_to_Blind(to_temp_acct: Boolean): Unit 
    {
        var bop: blind_transfer_op = blind_transfer_op()
        var blindconf: blind_confirmation = blind_confirmation()
        var feebase: Any? = fees.blindfees[0]
        var feeperinput: Any? = fees.blindfees[1]
        var feeperoutput: Any? = fees.blindfees[2]

        var CoinsIn: Array<BlindCoin> = BlindCoin.getCoinsSatisfyingAmount(
            from.coins, 
            (amount+feebase), 
            feeperinput, 
            feeperoutput)
        var totalfee = feebase + feeperoutput + feeperinput * CoinsIn.length
        var changeamount = BlindCoin.valueSum(CoinsIn - this.amount - totalfee)
        var changeoutputneeded = false
        if(changeamount > 0)
        {
            totalfee+=feeperoutput
            changeamount -= feeperoutput
            changeoutputneeded = true
        }
        assert(CoinsIn.length > 0 && changeamount >= 0)
        {"Insuficient spendable coins: ${(amount + totalfee)} needed; 
          ${BlindCoin.valueSum(from.coins)} available; 
          ${BlindCoin.valueSum(CoinsIn)} selected for use."}
        //blindconf.consumed_commits.push <HERE> - Study a bit about arrays in kotlin for a better form.
        // (..CoinsIn.map(a=>a.commitmentHex()))
        //var feeamountasset = <HERE> - Data structure for :
        /*
            let feeamountasset
            = {"amount":totalfee, "asset_id":this.asset.get("id")};
            bop.fee = feeamountasset;
        */
        println("Tx amount: ${amount} Change back: ${changeamount} Fee: ${totalfee}")
        //var Recipients = Array LIST//Data Class for :
        /*Recipients[0] = {"label":this.to.label, "markedlabel":this.to.markedlabel,
                         "amountdue":{"amount":this.amount,
                                      "asset_id":this.asset.get("id")},
                         "pubkey":this.to.pubkey
                        };*/
        if(changeoutputneeded)
        {
            Recipients.add(/*Data class to be made*/)//<HERE>
            /*
                        {"label":this.to.label, "markedlabel":this.to.markedlabel,
                         "amountdue":{"amount":this.amount,
                                      "asset_id":this.asset.get("id")},
                         "pubkey":this.to.pubkey
                        };
             */
        }
        //var blind_factors_in = CoinsIn.map(a => a.blinding_factor)
        var blind_factors_out = emptyArray<String>()
        var inputs = BlindCoin.getBlindInputsFromCoins(CoinsIn)
        bop.inputs = inputs;
        for(i in Recipients.indexes)
        {
            var needrangeproof = (Recipients.length > 1)
            var needblindsum = (i == Recipients.length-1)
            var Recipient = Recipients[i]

            var one_time_key = key.get_random_key();
            var to_key = Recipient.pubkey;
            var secret = one_time_key.get_shared_secret(to_key);  // 512-bits
            var child = hash.sha256(secret);        // 256-bit pub/priv key offset
            var nonce = one_time_key.toBuffer();    // 256-bits, (d in Q=d*G)
            var blind_factor = hash.sha256(child);  // (unless blindsum needed)
            if (needblindsum) 
            {
                blind_factor = StealthZK.BlindSum(blind_factors_in,
                                                  blind_factors_out);
            } else {
                blind_factors_out.add(blind_factor);
            }
            var amount = Recipient.amountdue.amount;
            /* <HERE> - Another amountasset data class needed. (or the same, we'll see)
            var amountasset = {"amount":amount, "asset_id":this.asset.get("id")};
                /*** console.log("Output " + (1+i) + " of " + Recipients.length
                                + " to " + Recipient.markedlabel
                                + "; amount = " + amount);
            */
            var sout = new blind_output;             // One output per recipient
            var nullowner = to_temp_acct && (i===0);// To be claimed in op 41
            /* <HERE> out.owner = data_class
            {"weight_threshold":nullowner?0:1,
                            "account_auths":[],
                            "key_auths":nullowner?[]:[[to_key.child(child),1]],
                            "address_auths":[]};
            */
            sout.commitment = StealthZK.BlindCommit(blind_factor,amount)
            if(needrangeproof){sout.range_proof = RangeProof.SignValue(amount,blind_factor, nonce)}
            else{sout.range_proof = emptyArray<Int>()}
            var meta = new blind_output_meta()
            meta.label = Recipient.label
            meta.auth = sout.owner
            meta.SetMemoData(amountasset, blind_factor, out.commitment);
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
        var feebase = fees.unblind[0]
        var whoto = to
        to = from
        amount += feebase
        var stage1 = Blind_to_Blind(true);
        to = whoto
        println("B2PUB: Stage 1 was ${stage1}")
        var bop = transfer_to_blind_op()
        var feeamount = feebase;
        //var feeamountasset = <HERE> - Data Class needed for: {"amount":feeamount, "asset_id":this.asset.get("id")}
        bop.fee = feeamountasset;
        var input_memo = stage1.output_meta[0].decrypted_memo
        var input_auth = stage1.output_meta[0].auth
        //^^ Need to search rather than assume position zero.
        var amount = input_memo.amount.amount - feeamount
        //amountasset = <HERE> - Data class needed for : {"amount":amount, "asset_id":this.asset.get("id")};
        bop.amount = amountasset;
        bop.to = to.id
        bop.blinding_factor = input_memo.blinding_factor
        //bop.inputs = arrayOf(<HERE> - Data class needed for: {"commitment":input_memo.commitment,"owner":input_auth})
        println("BOP: ${bop}")
        //<HERE> - Transaction builder etc. discuss with team.
    }
}