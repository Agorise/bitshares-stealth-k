/** class StealthAddress
 *
 *  BitShares Stealth Addresses and Tools
 *
 *  Status: Right now, this should be considered EXPERIMENTAL and NOT used for protecting real funds!!!
 *  Status: Right now, this should be considered EXPERIMENTAL and NOT used for protecting real funds!!!
 *
 *  Provides for the representation/interpretation "Stealth Addresses" in a variety of formats.
 *  Stores public key(s), and, if available, private keys associated with the address.  Provides
 *  tools for deriving "shared secrets" between address and an OTK "randomness" key, as well as
 *  "Child" addresses via a few different algorithms for computing TXO Authorization Keys.  Can
 *  also generate new addresses and keys.
 *
 *  Implements BSIP-1203 (https://github.com/bitshares/bsips/issues/91)
 *
 *  Supported address formats:
 *
 *  (All formats are a string header, e.g. "BTS", followed by Base58 encoding of byte fields
 *  indicated by consecutive repeated characters.)
 *
 *  1.) Standard:  BTSaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaCCCC
 *
 *      Encodes a single public key _A_ (33 bytes, SEC1 compressed) which serve both viewing and
 *      spending role, followed by a 4-byte checksum.
 *
 *  2.) Monero-Style (split Viewing/Spending):
 *
 *      BTSaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbCCCC
 *
 *      Encodes two public keys, _A_ and _B_ (33 bytes each).  _A_ serves the viewing role and _B_
 *      the spending role.  Also includes 4-byte checksum.
 *
 *  3.) Unlinkable Child:      (SUPPORT PENDING)
 *
 *      BTSaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbCCCC
 *
 *      This format also denotes a viewing and spending public key.  However, this address is a
 *      "child" of some parent address, following MRL-0006, which specifies an alternate algorithm
 *      for deriving TXO Auth Keys.  To signal that AuthKey generation should be different, the
 *      sign byte of key _B_ is manipulated in some way (T.B.D.) that prevents a naive wallet from
 *      correctly decoding the key, guaranteeing that only an "aware" wallet will recognize this
 *      address as valid.
 *
 *      (Suggested sentinel procedure: Bitshift left by two bits the sign byte for B.  Compute
 *      using un-shifted value, however, so that address will fail on checksum verification before
 *      even confusing the EC point decoder. TODO: finalize this procedure.)
 *
 *      MRL-0006 specifies a way of deriving a family of addresses from a single parent address in
 *      such a way that the following properties hold:
 *
 *        a.) The addresses are not linkable to each other or to the parent address,
 *        b.) A scanning wallet need compute the EC operations only ONCE per scanned TXO in order to
 *            check the entire family of addresses for a match, making it possible to use one-time
 *            addresses without incurring an additional scanning burden nor sacrificing privacy by
 *            communicating addresses that are visibly related. (N.B. this achieves unlinkability of
 *            the addresses themselves, e.g. when they might be published in a public forum, and is
 *            not about unlinkability of the payments. The payments are already unlinkable.)
 *
 *      To achieve point (b), an alternate AuthKey derivation is needed.  The manipulation of the
 *      sign byte is to signal that the alternate algorithm needs be used, and prevent naive wallets
 *      from accepting the address.
 *
 *
 *  CONSTRUCTION:
 *
 *
 *  StealthAddress object may be constructed in the following ways:
 *
 *  ->  StealthAddress(address : String)
 *
 *      Given an address as a string, this will extract the public keys and construct the object.
 *      In this case, the corresponding private keys will be unknown.  (They may be supplied later.)
 *
 *  ->  StealthAddress()
 *
 *      This will generate a new random address (TODO: actually should take an arg to indicate format)
 *      Private keys will also be generated and stored in the object.
 *
 *  ->  StealthAddress(viewkey : ECKey, spendkey = viewkey : ECKey)
 *
 *      This will construct the object from known keys.  If the ECKeys contain private keys, they will
 *      be retained. (TODO: should add a way to indicate format.)
 *
 *
 *  TOOLS:
 *
 *  ->  .toString() : String
 *
 *      Produce prefixed and Base58 encoded address string.
 *
 *  ->  .SharedSecret(OTK : ECKey) : Bytes[64]
 *
 *      Gives the 512-bit "shared secret" between the address's ViewKey and the OTK.  Either the ViewKey
 *      or the OTK must have a private key or else this will (TODO: should it trigger exception or return Bytes[0]?)
 *
 *  ->  .DeriveChild(index) : StealthAddress
 *
 *      Derives an unlinkable child address a la MRL-0006.
 *
 *  ->  .GenerateUnlinkableChildren(count : Integer)    (T.B.D.)
 *
 *      Generate a sequence of MRL-0006 child addresses and store in a member vector.  Allowed only on parent
 *      addresses.  Also produces the hash table needed to facilitate efficient scanning.)
 *
 *  ->  .GetTxAuthKey(OTK : ECKey) : ECKey
 *
 *      Generate the the AuthKey for a cXTO to this address using randomness key OTK.  To compute this, either
 *      OTK or this address's ViewKey must have a private key.  This method will correctly select the AuthKey
 *      derivation algorithm (normal or MRL-0006) based on the address format.
 *
 *  ->  .Recognize(OTK : ECKey, AuthKey : ECKey) : bool
 *
 *      Given an OTK and and AuthKey, this returns true if this address generates the AuthKey.  If this address
 *      object encapsulates a family of addresses, (e.g. MRL-0006 family, or an iterated SpendKey family), then
 *      this method checks the entire family.
 */

class StealthAddress() {



}