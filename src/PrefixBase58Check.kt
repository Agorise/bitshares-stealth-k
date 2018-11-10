import org.bitcoinj.core.Base58
import org.spongycastle.crypto.digests.RIPEMD160Digest

/**
 *  Encodes (and decodes) data into (or out of) a Prefixed Base58 with Checksum string representation.
 *  The prefix is a simple short character string.  The checksum is a truncated hash of the data payload,
 *  appended to the end of the payload before base58 encoding.
 *
 *  Encoding:
 *
 *    val dataPayload = ByteArray(...)
 *    println("PB58ck text: ${PrefixBase58Check("BTS", dataPayload)}") // .toString() is implied
 *
 *  Decoding:
 *
 *    val PB58Obj = PrefixBase58Check.fromString("BTS2fg2JK3jk34CG44c")
 *    val prefix : String = PB58Obj.prefix
 *    val payload : ByteArray = PB58Obj.payload
 *
 *  Differences from bitcoinj's native Base58 "encodeChecked" format:
 *    1. No version byte is prepended
 *    2. The checksum is a truncated RIPEMD160 and not a truncated double SHA256
 */
class PrefixBase58Check(val prefix : String, val payload : ByteArray = ByteArray(0)) {


    companion object {

        const val NUM_CHECK_BYTES = 4

        /**
         *  Decodes a PrefixBase58Check object from the given string.  Makes a few guesses at prefix length.
         *  (Currently tests for either a three char or four char prefix.)  Throws if cannot extract both a
         *  payload and prefix.  Prefix must be ASCII alphanumeric (no whitespace).
         */
        fun fromString(pb58str : String) : PrefixBase58Check {
            return try {fromStringAndPrefixLength(pb58str,3)}
                   catch(e: Throwable) {fromStringAndPrefixLength(pb58str, 4)}
        }
        /**
         *  This version decodes a PrefixBase58Check object from the given string, with the expectation of
         *  a specific prefix.  Will throw if the found prefix does not match the expected prefix.
         */
        fun fromString(pb58str : String, expectedPrefix : String) : PrefixBase58Check {
            val ret = fromStringAndPrefixLength(pb58str,expectedPrefix.length)
            require(expectedPrefix.contentEquals(ret.prefix))
            return ret
        }
        /*  Decode string and return root object; throws if cannot extract prefix of given length or if
         *  checksum not present or doesn't match. */
        private fun fromStringAndPrefixLength(fullStr : String, len : Int) : PrefixBase58Check {
            require(fullStr.length > len)
            val prefix = fullStr.substring(0,len)
            require(prefix.matches(Regex("[A-Za-z0-9]*")))
            val b58str = fullStr.substring(len)
            val checkedData = Base58.decode(b58str)
            require(checkedData.size >= NUM_CHECK_BYTES)
            val payload = checkedData.sliceArray(0..(checkedData.size - NUM_CHECK_BYTES - 1))
            val checkbytes = checkedData.takeLast(NUM_CHECK_BYTES).toByteArray()
            require(checkbytes.contentEquals(calculateChecksum(payload)))
            return PrefixBase58Check(prefix, payload)
        }
        /* Checksum used to MAC the address data before Base58'ing it.
         * Returns first four bytes of RIPEMD160(data) */
        private fun calculateChecksum(data: ByteArray): ByteArray {
            val checksum = ByteArray(160 / 8)
            val ripemd160Digest = RIPEMD160Digest()
            ripemd160Digest.update(data, 0, data.size)
            ripemd160Digest.doFinal(checksum, 0)
            return checksum.sliceArray(0..(NUM_CHECK_BYTES-1))
        }
    }

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
        var raw = this.payload
        val check : ByteArray = calculateChecksum(raw)
        raw += check
        return this.prefix + Base58.encode(raw)
    }


}
