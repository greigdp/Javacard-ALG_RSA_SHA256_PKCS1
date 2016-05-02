package com.github.greigdp.rsa_sig_sha256_pkcs1_15;

import javacard.framework.*;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

// This is an implementation of RSASSA-PKCS1-v1_5

public class main extends Applet
{
	// use unpadded RSA cipher for signing (so be careful with what you do!)
	Cipher cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
	// an RSA-2048 keypair
	KeyPair rsaPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
	RSAPrivateCrtKey rsaKeyPriv;
	RSAPublicKey rsaKeyPub;
	RandomData rng;
	// 256 byte buffer for producing signatures
	byte[] tempBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// 256 byte buffer to hold the incoming data (which will be hashed)
	byte[] dataBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// the DER prefix for a SHA256 hash in a PKCS#1 1.5 signature
	private static final byte[] SHA256_PREFIX = {
      (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d,
      (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
      (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
      (byte) 0x04, (byte) 0x02, (byte) 0x01, (byte) 0x05,
      (byte) 0x00, (byte) 0x04, (byte) 0x20
   };
	// support for SHA256
	MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	/**
	 * The class identifier for this applet, aka CLA
	 */
	final static byte APPLET_CLA = (byte)0x80;

	private main() {
		// set up a random data source
		rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		//rsaKeyPriv = (RSAPrivateCrtKey) rsaPair.getPrivate();
		//rsaKeyPub = (RSAPublicKey) rsaPair.getPublic();

	}

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new main().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		// grab P1 for checking if user wants modulus or exponent retrieved
		byte P1 = (byte) (buf[ISO7816.OFFSET_P1] & 0xFF);
		switch (buf[ISO7816.OFFSET_INS])
		{
		case (byte)0x00:
			// generate a new key
			gen_rsa_key();
			break;
		case (byte)0x01:
			// sign a given incoming message
			sign_message(apdu);
			break;
		case (byte)0x02:
			// retrieve the public key from the card
			getPublicRSA(apdu, P1);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	public void gen_rsa_key()
	{
		// generate an RSA keypair
		rsaPair.genKeyPair();
		// set the private and public components
		rsaKeyPriv = (RSAPrivateCrtKey) rsaPair.getPrivate();
		rsaKeyPub = (RSAPublicKey) rsaPair.getPublic();
		return;
	}

	// P1=0 for modulus, P1=1 for exponent
	private void getPublicRSA(APDU apdu, short P1)
	{
		// first check an RSA key is initialised
		if (!rsaKeyPub.isInitialized())
		{
			// RSA key isn't initialised for some reason... this is not OK
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}

		// get buffer access to APDU
		byte[] buffer = apdu.getBuffer();
		short length = 0;
		// determine if modulus or exponent is to be returned
		switch ((short) P1)
		{
		case 0x00: // get the modulus
			// move the modulus into the APDU buffer
			length = rsaKeyPub.getModulus(buffer, (short)0);
			break;
		case 0x01: // get the exponent
			// move the exponent into the APDU buffer
			length = rsaKeyPub.getExponent(buffer, (short)0);
			break;
		default:
			// return error
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		// send the buffer data back
		apdu.setOutgoingAndSend((short)0, length);
		return;
	}


	public void sign_message(APDU apdu)
	{
		if (!rsaKeyPriv.isInitialized())
		{
			// RSA key isn't initialised for some reason... this is not OK
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		// prepare for signing
		// signing being decryption using RSA (be careful here, ensure you understand PKCS#1.5 and don't sign "raw" data!)
		cipherRSA.init(rsaPair.getPrivate(), Cipher.MODE_DECRYPT);
		short length = 0;
		// get buffer access to APDU
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		// don't allow excessively long data to be signed, at least for now
		if (bytesRead > 256)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		// fetch the message to be signed into a temporary buffer
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, dataBuffer, (short)0, bytesRead);
		// pkcs1_sha256() will hash the input message of upto 255 bytes, and return a PKCS#1.5 digest to be signed
		pkcs1_sha256(dataBuffer, (short)0, bytesRead);
		// this has sets the tempBuffer as the data to sign

		// sign the contents of temporary buffer, send signature to APDU output buffer
		cipherRSA.doFinal(tempBuffer, (short)0, (short)256, buffer, (short)0);
		// clear the temp buffer
		Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)256, (byte)0x00);
		// clear the data buffer
		Util.arrayFillNonAtomic(dataBuffer, (short)0, (short)256, (byte)0x00);
		// return the signature
		apdu.setOutgoingAndSend((short)0, (short)256);
		return;
	}

	// this function will leave tempBuffer with the data to be signed
	public void pkcs1_sha256(byte[] toSign, short bOffset, short bLength)
	{
		// clear the hasher
		md.reset();

		// clear the temp buffer
		Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)256, (byte)0x00);
		// the format of a pkcs1#1.5 digest before signing is as follows:
		// (note that this is pre-computed for a sha256 hash length)

		// 2 bytes, 0x00, 0x01
		// padding (202 bytes of 0xFF)
		// byte 0x00
		// hash-type prefix is 19 bytes
		// hash is 32 bytes

		// therefore the padding contains 256-32-19-3 = 202 bytes
		tempBuffer[0] = (byte) 0x00;
		tempBuffer[1] = (byte) 0x01;
		// add in the padding
		Util.arrayFillNonAtomic(tempBuffer, (short)2, (short)202, (byte)0xFF);
		tempBuffer[204] = (byte) 0x00;
		// copy the DER prefix
		Util.arrayCopyNonAtomic(SHA256_PREFIX, (short)0, tempBuffer, (short)205, (short)SHA256_PREFIX.length);
		// now add the actual hash
		md.doFinal(toSign, bOffset, bLength, tempBuffer, (short)224);
		// the value to sign is in tempBuffer
	}

}
