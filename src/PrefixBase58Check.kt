import org.bitcoinj.core.Base58
import org.spongycastle.crypto.digests.RIPEMD160Digest

/**
 *
 */
class PrefixBase58Check(var prefix : String, var data : ByteArray = ByteArray(0)) {


    /** Get String representation of the Address.
     */
    override fun toString(): String {
        if (_encodedstring.isEmpty()) {
            _encodedstring = this.getPrefixedBase58CheckString()
        }
        return _encodedstring
    }
    var _encodedstring : String = ""

    /* This is a back-end to the toString() method. */
    fun getPrefixedBase58CheckString() : String {
        var raw = this.data
        val check : ByteArray = calculateChecksum(raw)
        raw += check
        return this.prefix + Base58.encode(raw)
    }

    /* Checksum used to MAC the address data before Base58'ing it.
     * Returns first four bytes of RIPEMD160(data) */
    private fun calculateChecksum(data: ByteArray): ByteArray {
        val checksum = ByteArray(160 / 8)
        val ripemd160Digest = RIPEMD160Digest()
        ripemd160Digest.update(data, 0, data.size)
        ripemd160Digest.doFinal(checksum, 0)
        return checksum.sliceArray(0..3)
    }


}