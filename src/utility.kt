import org.bitcoinj.core.DumpedPrivateKey
import org.bitcoinj.core.ECKey

fun ByteArray.toHex() = this.joinToString(separator = "") { it.toInt().and(0xff).toString(16).padStart(2, '0') }
fun String.hexStringToByteArray() = ByteArray(this.length / 2) { this.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
class PrivateKey
{
    companion object {
        var key = ECKey()
        fun fromWif(InputWIF: String): ECKey {
            key = DumpedPrivateKey.fromBase58(null, InputWIF).key

            return key
        }
    }
}