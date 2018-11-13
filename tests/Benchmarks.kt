import org.bitcoinj.core.ECKey

object Benchmarks {

    fun ScanningForTransactions(howManyBatches : Int, howManyKeys : Int) {

        require(howManyKeys>2)
        val keys = Array(howManyKeys-2) {ECKey()}

        keys.forEach { println("${it.publicKeyAsHex}") }

    }
}