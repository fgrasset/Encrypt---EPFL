package crypto;

import java.util.Random;


import static crypto.Helper.*;

public class Encrypt {
	
	public static final int CAESAR = 0;
	public static final int VIGENERE = 1;
	public static final int XOR = 2;
	public static final int ONETIME = 3;
	public static final int CBC = 4; 
	
	public static final byte SPACE = 32;
	
	final static Random rand = new Random();
	
	//-----------------------General-------------------------
	
	/**
	 * General method to encode a message using a key, you can choose the method you want to use to encode.
	 * @param message the message to encode already cleaned
	 * @param key the key used to encode
	 * @param type the method used to encode : 0 = Caesar, 1 = Vigenere, 2 = XOR, 3 = One time pad, 4 = CBC
	 * 
	 * @return an encoded String
	 * if the method is called with an unknown type of algorithm, it returns the original message
	 */
	public static String encrypt(String message, String key, int type) {
		
		String message_cleaned = Helper.cleanString(message);
		byte[] messageBytes = Helper.stringToBytes(message_cleaned);
		byte[] keyBytes = Helper.stringToBytes(key);
		
		switch(type) {
		case CAESAR:
			return bytesToString(caesar(messageBytes, keyBytes[0], false));
			
		case VIGENERE:
			return bytesToString(vigenere(messageBytes, keyBytes, false));
			
		case XOR:
			return bytesToString(xor(messageBytes, keyBytes[0], false));
			
		case ONETIME:
			byte[] pad = generatePad(messageBytes.length);
			return bytesToString(oneTimePad(messageBytes, pad));
			
		case CBC:
			byte[] iv = generatePad(4);
			return bytesToString(cbc(messageBytes, iv));
			
		default:
			System.out.print(message);
		}
		
		return  null;
	}
	
	
	//-----------------------Caesar-------------------------
	
	/**
	 * Method to encode a byte array message using a single character key
	 * the key is simply added to each byte of the original message
	 * @param plainText The byte array representing the string to encode
	 * @param key the byte corresponding to the char we use to shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key, boolean spaceEncoding) {
		
		assert(plainText != null && plainText.length > 0);
		
		byte[] cipherText = new byte [plainText.length];
		
		for (int i = 0; i < plainText.length; i++) {
			if (!spaceEncoding && plainText[i] == SPACE ) {
				cipherText[i] = SPACE;
				continue;
		    }
			cipherText[i] = (byte) (plainText[i] + key);
		}
		return cipherText;
	}
	
	/**
	 * Method to encode a byte array message  using a single character key
	 * the key is simply added  to each byte of the original message
	 * spaces are not encoded
	 * @param plainText The byte array representing the string to encode
	 * @param key the byte corresponding to the char we use to shift
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key) {
		
		assert(plainText != null && plainText.length > 0);
		
		byte[] cipherText = caesar(plainText, key, false);
		
		return cipherText;
	}
	
	
	//-----------------------XOR-------------------------
	
	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * @param plaintext the byte array representing the string to encode
	 * @param key the byte we will use to XOR
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key, boolean spaceEncoding) {
		
		assert(plainText != null && plainText.length > 0);
		
		byte[] cipherText = new byte[plainText.length];
		
		for (int i = 0; i < plainText.length; i++) {
			if (!spaceEncoding && plainText[i] == SPACE) {
				cipherText[i] = SPACE;
				continue;
			}
			cipherText[i] = (byte) (plainText[i] ^ key);
		}
		
		return cipherText;
	}
	
	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * spaces are not encoded
	 * @param key the byte we will use to XOR
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key) {
		
		assert(plainText != null && plainText.length > 0);
		
		byte[] cipherText = xor(plainText, key, false);
		
		return cipherText; 
	}
	
	
	//-----------------------Vigenere-------------------------
	
	/**
	 * Method to encode a byte array using a byte array keyword
	 * The keyword is repeated along the message to encode
	 * The bytes of the keyword are added to those of the message to encode
	 * @param plainText the byte array representing the message to encode
	 * @param keyword the byte array representing the key used to perform the shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array 
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword, boolean spaceEncoding) {
		
		assert(plainText != null && plainText.length > 0);
		assert(keyword != null && keyword.length > 0);
		
		byte[] cipherText = new byte [plainText.length];
		
		int index_key = 0;
		
		for (int i = 0; i < cipherText.length; i++) {
			if (!spaceEncoding && plainText[i] == SPACE) {
				cipherText[i] = SPACE;
				continue;
			}
			
			cipherText[i] = (byte) (plainText[i] + keyword[index_key]);
			
			index_key ++;
			index_key %= keyword.length;		 // modulo always returns the value index_key, except when index_key = keyword.length (it will return 0)
		}

		return cipherText;
	}
	
	/**
	 * Method to encode a byte array using a byte array keyword
	 * The keyword is repeated along the message to encode
	 * spaces are not encoded
	 * The bytes of the keyword are added to those of the message to encode
	 * @param plainText the byte array representing the message to encode
	 * @param keyword the byte array representing the key used to perform the shift
	 * @return an encoded byte array 
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword) {
		
		assert(plainText != null && plainText.length > 0);
		assert(keyword != null && keyword.length > 0);
		
		byte[] cipherText = vigenere(plainText, keyword, false);
		
		return cipherText;
	}
	
	
	
	//-----------------------One Time Pad-------------------------
	
	/**
	 * Method to encode a byte array using a one time pad of the same length.
	 *  The method  XOR them together.
	 * @param plainText the byte array representing the string to encode
	 * @param pad the one time pad
	 * @return an encoded byte array
	 */
	public static byte[] oneTimePad(byte[] plainText, byte[] pad) {
		
		assert(pad.length >= plainText.length);
		
		byte[] cipherText = new byte[plainText.length];
		
		for (int i = 0; i < plainText.length; i++) {
			cipherText[i] = (byte) (plainText[i] ^ pad[i]);
		}

		return cipherText;
	}

	
	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method applying a basic chain block counter of XOR without encryption method. Encodes spaces.
	 * @param plainText the byte array representing the string to encode
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return an encoded byte array
	 */
	public static byte[] cbc(byte[] plainText, byte[] iv) {
		
		assert(plainText != null && plainText.length > 0);
		
		int last_block_index = 0;
		
		byte[] cipherText = new byte[plainText.length];
		
		boolean use_iv = true;
		
		for (int i = 0; i < plainText.length; i += iv.length) {
			
			for (int j = 0; j < iv.length; j++) {
				byte b = 0;   								// byte we want to crypt with
				
				if (i + j >= cipherText.length) {   		// position of the byte
					return cipherText;
				}
				
				// First iteration, use IV
				if (use_iv) {
					b = iv[j];
				} else {
					b = cipherText[last_block_index + j];  // index inside a block
				}
				
				cipherText[i + j] = (byte) (plainText[i + j] ^ b);
			}
			
			use_iv = false;									// we won't use IV anymore
			last_block_index = i;							
		}

		return cipherText; 
	}
	
	
	/**
	 * Generate a random pad/IV of bytes to be used for encoding
	 * @param size the size of the pad
	 * @return random bytes in an array
	 */
	public static byte[] generatePad(int size) {
		
		byte[] pad = new byte[size];
		
		for (int i = 0; i < size; i++) {
			pad[i] = (byte) rand.nextInt(256);
		}
		
		return pad;
	}	
}
