object TestSuite {

    @JvmStatic
    fun main(args: Array<String>) {
        println("Heeeelllllooooowwwwww")

        var blindfact : Int = 55
        var amount : Int = 4

        var C : Int = StealthZK.BlindCommit(blindfact, amount)

        println("Commitment is ${C}")

    }

}
