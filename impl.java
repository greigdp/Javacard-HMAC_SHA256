package com.github.greigdp.hmacsha256;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;

// a software implementation of HMAC_SHA256 for JavaCard
// note that this uses a fixed 256-bit (32 byte) key
// The full handling of shorter and longer keys is NOT implemented here
// Therefore this is not a full implementation of the RFC for HMAC!
// It is compatible with reference implementations when
// - the hash function used is SHA256
// - the HMAC key is 256 bits long

// also note that it copies the HMAC key into transient memory during processing,
// which may have security implications, although is realistically unavoidable

public class hmac_sha256 extends Applet
{
	final static short LEN_AES_256_KEY = (short) 32;
	final static short LEN_TEMP_BUFFER = (short) 256;
	final static short LEN_HMAC_BLOCK = (short) 64;
	AESKey hmacKey = (AESKey) KeyBuilder.buildKey (KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
	MessageDigest md;
	byte[] tempBuffer = JCSystem.makeTransientByteArray(LEN_TEMP_BUFFER, JCSystem.CLEAR_ON_DESELECT);
	RandomData rng;
	byte[] rndBuffer = JCSystem.makeTransientByteArray((short) LEN_AES_256_KEY, JCSystem.CLEAR_ON_DESELECT);
	byte[] ipadK = JCSystem.makeTransientByteArray(LEN_HMAC_BLOCK, JCSystem.CLEAR_ON_DESELECT);
	byte[] opadK = JCSystem.makeTransientByteArray(LEN_HMAC_BLOCK, JCSystem.CLEAR_ON_DESELECT);

	public hmac_sha256()
	{
		rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		md = MessageDigest.getInstance((byte) 4, false); // 4 = MessageDigest.ALG_SHA_256, but there is some strange compile bug for some cards, so leaving this as 4 for now
		rng.generateData(rndBuffer, (short)0, LEN_AES_256_KEY);
		// set the device MAC key to the randomly generated value
		hmacKey.setKey(rndBuffer, (short) 0);
		// now clear rndBuffer
		Util.arrayFillNonAtomic(rndBuffer, (short)0, LEN_AES_256_KEY, (byte)0x00);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new hmac_sha256().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case (byte)0x00:
			break;
		case (byte)0x01:
			calc_hmac_sha256(apdu);
			break;
    case (byte)0x02: // WARNING: This is for debugging/POC only, do not leave it in as it exposes the raw key!
			dump_hmac_key(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private short hmac_sha256(AESKey hmacKey, byte[] msg, short msgOffset, short msgLength, byte[] response, short responseOffset)
	{
		final byte ipad = 0x36;
		final byte opad = 0x5C;
		// hmac key is at hmacKey (param) - copy it to rndBuffer
		hmacKey.getKey(rndBuffer, (short) 0);

		for (short i=0; i < LEN_HMAC_BLOCK; i++)
		{
			// for each byte of the key, work out the pad byte
			if (i >= LEN_AES_256_KEY)
			{
				ipadK[i] = (byte) (0x00 ^ ipad);
				opadK[i] = (byte) (0x00 ^ opad);
			}
			else
			{
				ipadK[i] = (byte) (rndBuffer[i] ^ ipad);
				opadK[i] = (byte) (rndBuffer[i] ^ opad);
			}
		}
		// clear the rndBuffer - it can be used now for digest outputs
		Util.arrayFillNonAtomic(rndBuffer, (short)0, LEN_AES_256_KEY, (byte)0x00);
		// first find H(ipadK, msg), and output to byte 32 of tempBuffer
		// copy message after ipadK
		Util.arrayCopyNonAtomic(ipadK, (short)0, tempBuffer, (short)0, LEN_HMAC_BLOCK);
		// now place message after it
		Util.arrayCopyNonAtomic(msg, msgOffset, tempBuffer, LEN_HMAC_BLOCK, msgLength);
		md.reset();
		md.doFinal(tempBuffer, (short)0, (short)(LEN_HMAC_BLOCK + msgLength), rndBuffer, (short)0);
		// now place it in position in tempBuffer
		Util.arrayCopyNonAtomic(rndBuffer, (short)0, tempBuffer, LEN_HMAC_BLOCK, LEN_AES_256_KEY);
		//now find H(opadK, rndBuffer)
		// copy in the oPadk
		Util.arrayCopyNonAtomic(opadK, (short)0, tempBuffer, (short)0, LEN_HMAC_BLOCK);
		md.reset();
		short outputLength;
		outputLength = md.doFinal(tempBuffer, (short)0, (short) (LEN_AES_256_KEY + LEN_HMAC_BLOCK), response, responseOffset);
		md.reset();
		// clear the temporary buffer
		Util.arrayFillNonAtomic(tempBuffer, (short)0, LEN_TEMP_BUFFER, (byte)0x00);
		// clear the rndBuffer
		Util.arrayFillNonAtomic(rndBuffer, (short)0, LEN_AES_256_KEY, (byte)0x00);
		return outputLength;
	}

	private void calc_hmac_sha256(APDU apdu)
	{
		// get buffer access to APDU
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		if (bytesRead > 256)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte[] response = JCSystem.makeTransientByteArray(LEN_AES_256_KEY, JCSystem.CLEAR_ON_DESELECT);
		hmac_sha256(hmacKey, buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF), response, (short) 0);
		// now copy the result
		Util.arrayCopyNonAtomic(response, (short)0, buffer, (short)0, LEN_AES_256_KEY);
		// now clear rndBuffer
		Util.arrayFillNonAtomic(rndBuffer, (short)0, LEN_AES_256_KEY, (byte)0x00);
		apdu.setOutgoingAndSend((short)0, LEN_AES_256_KEY);
	}

  // WARNING: This function is only for the POC, to let you check the HMAC on an independent implementation
	private void dump_hmac_key(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		hmacKey.getKey(buffer, (short) 0);
		apdu.setOutgoingAndSend((short)0, LEN_AES_256_KEY);

	}

}
