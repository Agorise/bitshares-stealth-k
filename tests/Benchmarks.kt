import org.bitcoinj.core.ECKey
import kotlin.system.measureTimeMillis

object Benchmarks {

    fun ScanningForTransactions(howManyBatches : Int = 4, howManyKeys : Int = 100) {

        require(howManyKeys>2)
        require(howManyBatches>=0)

        println("")
        println("===========================================================")
        println("** Benchmark: Scanning Tx Metadata for Owned Tx Outputs: **")
        println("===========================================================")

        println("*\n* Generating ${howManyKeys-2} red-herring keys to be our 'non-matches':")

        var timeMillis : Long = System.currentTimeMillis()
        var batchTimeMillisList = MutableList(0) {0L}

        val keys = MutableList(howManyKeys-2) {ECKey()}
        timeMillis = System.currentTimeMillis() - timeMillis
        println("* ...Allocated ${howManyKeys-2} keys in $timeMillis milliseconds.\n*")

        println("* Generating Bob StealthAddress:")
        val bobSA = StealthAddress()
        println("* ...Bob:  ${bobSA}\n*")

        println("* Generating an OTK and TxAuthKey for an output to Bob, and adding to key vector:")
        val OTK = ECKey()
        val TxAuthKey = bobSA.getTxAuthKey(OTK)
        println("* ...OTK:  ${PrefixBase58Check("OTK",OTK.pubKey)}")
        println("* ...TAK:  ${PrefixBase58Check("BTS",TxAuthKey.pubKey)}\n*")
        keys.add(OTK)
        keys.add(TxAuthKey)

        val howManyPairings = keys.size * keys.size
        println("* ${keys.size} Keys may be paired in $howManyPairings (OTK, TAK) testable combinations.")
        println("* (Of which only one pairing should be 'recognized' as beloning to Bob.)\n*")

        println("*\n* *************************")
        println("* STARTING $howManyBatches BATCHES:\n*")

        for (i in 1..howManyBatches) {
            println("*   ** STARTING: Batch $i: **\n*")
            var pairsTested : Int = 0
            var pairsMatched : Int = 0
            timeMillis = System.currentTimeMillis()
            for (k1 in 0 until howManyKeys) {
                for (k2 in 0 until howManyKeys) {
                    if (bobSA.recognizeTxAuthKey(keys[k1], keys[k2])) {
                        pairsMatched += 1
                        println("*   Match on (key[$k1], key[$k2]).")
                    }
                    pairsTested += 1
                }
            }
            timeMillis = System.currentTimeMillis() - timeMillis
            println("*   Batch $i Summary: Time $timeMillis ms; Tested $pairsTested key pairings; Matched on $pairsMatched combo${if(pairsMatched==1){""}else{"s"}}.\n*")
            batchTimeMillisList.add(timeMillis)
        }
        val totalTimeSeconds = batchTimeMillisList.sum().div(1000.0)
        val timePerNetworkDay = totalTimeSeconds / (howManyBatches*howManyPairings) * (14*60*60*24)

        println("*\n* *************************")
        println("* BENCH SUMMARY:  Total Time: $totalTimeSeconds sec, over ${howManyBatches} batches of $howManyPairings simulated TXOs.\n*")
        println("*             Avg Batch Time: ${batchTimeMillisList.average().div(1000.0)} sec.")
        println("*                    Fastest: ${batchTimeMillisList.max()!!.div(1000.0)} sec.")
        println("*                    Slowest: ${batchTimeMillisList.min()!!.div(1000.0)} sec.\n*")
        println("*   Scanning Time per Network-Activity-Day:  $timePerNetworkDay sec, at Bitcoin levels of 14 TXOs/Second.")

        println("*\n* CONCLUDES: BENCH: ScanningForTransactions.")
        println("* ////////\n")

    }
}