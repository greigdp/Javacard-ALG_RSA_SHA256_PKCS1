# SHA256 PKCS#1 v1.5 on JavaCard

Note: This should be considered a proof-of-concept, not a production-ready implementation.

## Motivation
Most Javacard smartcards have a fairly limited set of supported cryptographic algorithms. For example, looking at [version 2.2 of the spec](https://www.win.tue.nl/pinpasjc/docs/apis/jc222/javacard/security/Signature.html), you will notice that most of the signatures supported are either

* very old
* very weak
* (or both)

The symmetric signatures go as low as 4-byte (32-bit) DES MACs, and the asymmetric signatures support SHA1 and MD5 digests. Neither of these is current or recommended in 2016 (or many years prior to this).

It would therefore be nice to have some more modern variants of these signature functions, which allow for use with less broken hashes. Bear in mind that collision resistance is a critical property of a hash when used in a signature - if a collision can be found, a signature can be presented along with a colliding message.

Recent software (such as [Let's Encrypt](https://www.letsencrypt.org)) uses RSA signatures in order to sign SSL requests with an account key. There is therefore an obvious desire to be able to store this account key on an external smartcard or HSM, to prevent the account key from being stolen.

Unfortunately, Let's Encrypt appears to use RSA PKCS#1 v1.5 signatures, which were not supported on the Javacard I had lying around. While this is, in theory at least, [available in Javacard 3.0.1](https://www.fi.muni.cz/~xsvenda/jcsupport.html), it seems that card support is relatively limited. Therefore, there's a need for an implementation of RSA signatures, using SHA256 hashes, with the PKCS#1 v1.5 padding scheme. This is an attempt to make a useful implementation of this signature scheme, with a view to making a smartcard applet which supports holding and signing using a Let's Encrypt account key.

## Implementation

This is a proof-of-concept implementation of RSASSA-PKCS1-v1_5 on JavaCard, using as much of the safe inbuilt functionality as possible. It is not presented here as an easy-to-use library, in order to discourage unaudited "drag and drop" usage.

There is also no error handling for missing algorithms - this is just a POC.

### Hashing

An incoming message of up to 255 bytes is accepted as an incoming APDU. The SHA256 hash of this is calculated, using the card's onboard SHA256 hashing support. Since my card supported SHA256, I've not made a software implementation of it.

### Padding

After hashing the message using SHA256, the hash is appropriately prefixed and padded per the PKCS#1 v1.5 padding standard. The result is a 256-byte message, ready for signing.

### Signing

The RSA signature is carried out using the raw, unpadded RSA decrypt operation provided by the smartcard. Again, this assumes that your Javacard smartcard implements Cipher.ALG_RSA_NOPAD, although the [compatibility matrix](https://www.fi.muni.cz/~xsvenda/jcsupport.html) seems to indicate that every card supports this, except for a single DES-only card.

The signature is produced as the decryption of the PKCS#1 v1.5 padded digest, and this signature is returned through the APDU interface as a 256-byte long signature.

### Verification

To allow for verification of this solution, an example Python script is enclosed. This contains a (hard-coded) place to put the RSA public key exponent and modulus, as well as the signature retrieved from the card. It forms an RSA public key object from the modulus and exponent, and then verifies the signature using this, for a given message.

### Testing

To test using GlobalPlatform,

1. Install the applet

        $ java -jar gp.jar --default --install <compiled_name.cap>

2. Instruct the card to generate an RSA-2048 key

        $ java -jar gp.jar --applet 001122334455667700 -a 80000000 -d

3. Retrieve the public key components from the card for verification (this returns 3 bytes, the exponent)

        $ java -jar gp.jar --applet 001122334455667700 -a 8002010003 -d

4. Retrieve the public key components from the card for verification (this returns 256 bytes, the modulus)

        $ java -jar gp.jar --applet 001122334455667700 -a 80020000FF -d

5. Generate a signature of a message (upto 255 bytes is possible) - for example, let's do the 5 bytes: `{0x01, 0x02, 0x03, 0x04, 0x05}`

        $ java -jar gp.jar --applet 001122334455667700 -a 80010000050102030405FF -d

6. Place the returned values into the Python script and ensure signature verification succeeds. Ensure the public key, message and signature values are all updated properly.
