class Transfer(from: String, to: String, amount: Int, transaction_type: Int)
{
    val From = from
    val To = to
    val Amount = amount
    val Transaction_Type = transaction_type
    var Valid = false
    private fun blind(): Unit {
        /* Todo */
    }
    private fun stealth(): Unit {
        /* Todo */
    }
    init{
        if(From.isNotEmpty() && To.isNotEmpty() && Amount > 0 && Transaction_Type > 0 && Transaction_Type <3)
        {
            this.Valid = true
        }
        else{throw(Exception("Invalid input passed to transfer class!"))}
    }
    fun execute(): Unit {
        if(Transaction_Type == 1)
        {
            this.blind()
        }
        if(Transaction_Type > 2)
        {
            this.stealth()
        }
    }
}