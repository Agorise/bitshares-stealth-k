import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import kotlin.math.min

/**
 *  Class BlindCommitment
 *
 *  Encapsulates the OPENING information of a Pedersen commitment, and can compute the commitment's encoding
 *  as an ECPoint.  Also provides commitment math operations (blind sums, etc.)
 *
 *  Note: a BlindCommitment differs from a general commitment in that it commits to a random blinding factor
 *  as well as one or more value messages.
 *
 *  C = blind * G + val1 * H1 + val2 * H2 + ...
 *
 *  config:  StealthConfig object specifying curve and value bounds, etc.
 *
 *  randomness:  A BigInteger between 1 and the curve order to use as a blinding factor. Generation of this
 *               random value is up to the user.
 *
 *  values:  These are the values to commit to.  Generally there is just one (e.g. Confidential Transactions).
 *           But there may be more than one, e.g. in the case of Confidential Assets.
 *
 *  generators:  The generators that the values will multiply.  By default we use config.G2 (Maxwell's alternate
 *               generator), but in the case of CA each asset has its own generator.
 */
class BlindCommitment(val config: StealthConfig,
                      var randomness: BigInteger,
                      var values: Array<BigInteger>,
                      var generators: Array<ECPoint> = Array<ECPoint>(min(1,values.size),{config.G2})) {



    /**
     *  Get commitment as an ECPoint
     */
    fun getECCommitment() : ECPoint {

        check(values.size == generators.size)
          {"Length of |values| array and |generators| array must match."}
        check(randomness > BigInteger.ZERO)   // TODO: May need to relax to >= for public fee commitments
          {"Randomness value out of allowed range."}
        check(randomness < config.curveOrder) // TODO: Should err or should silent wrap? (should error)
          {"Randomness value out of allowed range."}
        for (value in values) {
            check(value <= config.maxProvable)
              {"Value message exceeds config.maxProvable."}
            check(value <= config.curveOrder)
              {"Value message exceeds config.curveOrder."}
            check(value >= BigInteger.ZERO)
              {"Value message must be non-negative"}
        }

        var C = config.G.multiply(randomness)
        for (i in 0..values.lastIndex) {
            C = C.add(generators[i].multiply(values[i]))
        }
        check(!C.isInfinity) {"Result is point at infinity."}
        return C

    }

}