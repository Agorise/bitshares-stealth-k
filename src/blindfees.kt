/**
 * This is temporary convenience to centralize the determination of fees
 * for blinded TXs.  There may be an existing mechanism that is better.
 *
 * BAD CODE in here -- we are hard-coding the fees. These need to be
 * queried from the blockchain before production release. (Especially
 * since fees can differ for lifetime members. Hard-coding obviously
 * won't work.)
 *
 * TODO: work out how to query blockchain for fees.  Shouldn't be
 * difficult.
 */

class BlindFees()
{
    var blindfees: Array<Int> = arrayOf(100, 0, 500000)
    var unblind: Array<Int> = arrayOf(100)
    var chainid: String = "Not_Implemented_Yet."
    var fees: BlindFees = BlindFees()

    //GET CHAIN ID TODO: <HERE>
    init
    {
            if (chainid.compareTo("4018d784") == 0) {
                println("Using blind fee structure for main net 4018d784")
                // TODO: Still need to get these fees *properly* (and also check
                // for lifetime member status which reduces fees.)
                blindfees = arrayOf(500000, 0, 500000); // Base, per-input, per-output
                unblind = arrayOf(254933);
            }
            if (chainid.compareTo("9cf6f255")==0) {
                /***/
                println("Using blind fee structure for Agorise pre-alpha test net 9cf6f255.")
                // TODO: Still need to get these fees *properly* (and also check
                // for lifetime member status which reduces fees.)
                blindfees = arrayOf(500000, 0, 500000) // Base, per-input, per-output
                unblind = arrayOf(500000)           // Cost to unblind a commitment
            }
    }
}
