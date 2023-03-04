package crypto;

import static crypto.Helper.bytesToString;


import static crypto.Helper.stringToBytes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class Decrypt {
	
	
	public static final int ALPHABETSIZE = Byte.MAX_VALUE - Byte.MIN_VALUE + 1 ; //256
	public static final int APOSITION = 97 + ALPHABETSIZE/2; 
	
	public static final byte SPACE = 32;
	
	//source : https://en.wikipedia.org/wiki/Letter_frequency
	public static final double[] ENGLISHFREQUENCIES = {0.08497,0.01492,0.02202,0.04253,0.11162,0.02228,0.02015,0.06094,0.07546,0.00153,0.01292,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.07587,0.06327,0.09356,0.02758,0.00978,0.0256,0.0015,0.01994,0.00077};
	
	/**
	 * Method to break a string encoded with different types of cryptosystems
	 * @param type the integer representing the method to break : 0 = Caesar, 1 = Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in the list above.
	 */
	public static String breakCipher(String cipher, int type) {
		
	byte[] cipherText = stringToBytes(cipher);
		
		switch(type) {
		case Encrypt.CAESAR:
			byte key = Decrypt.caesarWithFrequencies(cipherText);
			return bytesToString(Encrypt.caesar(cipherText, key));
			
		case Encrypt.VIGENERE:
			byte[] plainText = vigenereWithFrequencies(cipherText);
			return bytesToString(plainText);
		
		case Encrypt.XOR:
			return arrayToString(xorBruteForce(cipherText));
		
		default :
			System.out.println("Choose a cryptosystem between 0 and 2 (CAESAR, VIGENERE, XOR)");
		}
		

		return null;
	}
	
	
	/**
	 * Converts a 2D byte array to a String
	 * @param bruteForceResult a 2D byte array containing the result of a brute force method
	 */
	public static String arrayToString(byte[][] bruteForceResult) {
		
		String s = "";
		for (int i = 0; i < bruteForceResult.length; i++) {
			s += Helper.bytesToString(bruteForceResult[i]);
			s += System.lineSeparator();
		}

		return s;
	}
	
	
	//-----------------------Caesar-------------------------
	
	/**
	 *  Method to decode a byte array  encoded using the Caesar scheme
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return a 2D byte array containing all the possibilities
	 */
	public static byte[][] caesarBruteForce(byte[] cipher) {
		
		byte[][] plainTexts = new byte[256][cipher.length];
		int i = 0;
		for (int key = -128; key <= 127; key++) {
			plainTexts[i] = Encrypt.caesar(cipher, (byte) key);
			i++;
		}

		return plainTexts;
	}	
	
	
	/**
	 * Method that finds the key to decode a Caesar encoding by comparing frequencies
	 * @param cipherText the byte array representing the encoded text
	 * @return the encoding key
	 */
	public static byte caesarWithFrequencies(byte[] cipherText) {
		
		float[] freq = computeFrequencies(cipherText);
//		System.out.print("computeFrequencies : ");
//		for (int i = 0; i < freq.length; ++i) {
//			System.out.print(freq[i]);
//		}
//		System.out.println();
		byte key = caesarFindKey(freq);

		return key; 
	}
	
	/**
	 * Method that computes the frequencies of letters inside a byte array corresponding to a String
	 * @param cipherText the byte array 
	 * @return the character frequencies as an array of float
	 */
	public static float[] computeFrequencies(byte[] cipherText) {
		
		float[] result = new float[256];
		
		for (int i = 0; i < cipherText.length; i++) {
			if (cipherText[i] == SPACE) {
				continue;
			}
			result[cipherText[i] + 128] += 1;
		}
		for (int i = 0; i < result.length; i++) {
			result[i] /= cipherText.length;	
		}

		return result;
	}
	
	
	/**
	 * Method that finds the key used by a  Caesar encoding from an array of character frequencies
	 * @param charFrequencies the array of character frequencies
	 * @return the key
	 */
	public static byte caesarFindKey(float[] charFrequencies) {
		
		byte bestKey = 0;
		float bestProduct = 0;
		
		for (int i = 0; i < 256; i++) {
			float product = 0;
			int k = i;
			
			for (int j = 0; j < ENGLISHFREQUENCIES.length; j++) {
				product += ENGLISHFREQUENCIES[j] * charFrequencies[k++];
				
				if (k == 256) {
					k = 0;
				}
			}
			
			if (product > bestProduct) {
				bestProduct = product;
				bestKey = (byte) (APOSITION - i);
			}
		}
		
		return bestKey;
	}
	
	
	
	//-----------------------XOR-------------------------
	
	/**
	 * Method to decode a byte array encoded using a XOR 
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return the array of possibilities for the clear text
	 */
	public static byte[][] xorBruteForce(byte[] cipher) {
		
		byte[][] plainTexts = new byte [256][cipher.length];
		int i = 0;
		
		for (int key = -128; key <= 127; key++) {
			plainTexts[i] = Encrypt.xor(cipher, (byte) key);
			i++;
		}
		
		return plainTexts;
	}
	
	
	
	//-----------------------Vigenere-------------------------
	// Algorithm : see  https://www.youtube.com/watch?v=LaWp_Kq0cKs	
	/**
	 * Method to decode a byte array encoded following the Vigenere pattern, but in a clever way, 
	 * saving up on large amounts of computations
	 * @param cipher the byte array representing the encoded text
	 * @return the byte encoding of the clear text
	 */
	public static byte[] vigenereWithFrequencies(byte[] cipher) {
		
		List<Byte> cipherText = removeSpaces(cipher);
		
		int keyLength = vigenereFindKeyLength(cipherText);
		
		byte[] keyBytes = vigenereFindKey(cipherText, keyLength);
		
		byte[] plainTextBytes = Encrypt.vigenere(cipher, keyBytes);
		
		
		return plainTextBytes;
	}
	
	
	
	/**
	 * Helper Method used to remove the space character in a byte array for the clever Vigenere decoding
	 * @param array the array to clean
	 * @return a List of bytes without spaces
	 */
	public static List<Byte> removeSpaces(byte[] array){
		
		List<Byte> result = new ArrayList<Byte>();
		
		for (int i = 0; i < array.length; i++) {
			if (array[i] != SPACE) {
				result.add(array[i]);
			}
		}
		
		return result;
	}
	
	
	//First step : counting how many times characters coincide
	public static int[] getCoincidenceArray(List<Byte> cipherText) {
		
		int[] coincidences = new int[cipherText.size()];
		
		for (int i = 1; i < cipherText.size(); i++) {						//sert à décaler l'index de comparaison de 1
			for (int j = 0, k = i; k < cipherText.size(); j++, k++) {		//sert à itérer dans le cipherText (k<cipherText.size() pour pas de out of bound
																			//k représente la copy de cipherText, et j l'original
				if (cipherText.get(k) == cipherText.get(j)) {
					coincidences[i - 1]++;     								//stock the number of coincidences
				}
			}
		}

		return coincidences;
	}
	

	/**
	 * Method that computes the key length for a Vigenere cipher text.
	 * @param cipher the byte array representing the encoded text without space
	 * @return the length of the key
	 */
	public static int vigenereFindKeyLength(List<Byte> cipher) {
		
		//Second step : Compute the list of local maximum
		int[] coincidenceArray = getCoincidenceArray(cipher);
		List<Integer> maxLocIndices = new ArrayList<Integer>();
		System.out.print("coincidences : ");
		for(int l = 0; l < coincidenceArray.length; ++l) {
			System.out.print(" " + coincidenceArray[l]);
		}
		System.out.println();
		
		
		for (int i = 0; i < Math.ceil(coincidenceArray.length / 2); i++) {
			int maxLeft = Integer.MIN_VALUE;
			int maxRight = Integer.MIN_VALUE;
			//Calcul des maximum à gauche
			System.out.print("indice de coincidence : " + coincidenceArray[i] + " ");			//cas où index 0, 
			if (i == 1) {																		//cas où index 1 pour maxLeft
				maxLeft = coincidenceArray[0];													//prend le max à gauche
				System.out.println("maxLeft : " + maxLeft);
			} else if (i > 1) {																	//cas où index de 2	pour maxLeft
				maxLeft = Math.max(coincidenceArray[i - 2], coincidenceArray[i - 1]);			//prends le maximum entre les deux valeurs à gauche de i
				System.out.print("maxLeft : " + maxLeft + " ");
			}
			
			//Calcul des maximum à droite
			if (i < coincidenceArray.length - 3) {												//cas où index a encore au moins deux valeurs à droite
				maxRight = Math.max(coincidenceArray[i + 1], coincidenceArray[i + 2]);			//prends le maximum entre les deux valeurs à droite de i
				System.out.println("maxRight : " + maxRight);
			} else if (i == coincidenceArray.length - 2) {										//cas où index à moins que deux valeurs à droite
				maxRight = coincidenceArray[i + 1];
				System.out.println("maxRight : " + maxRight);
			}
			
			if (coincidenceArray[i] > maxLeft && coincidenceArray[i] > maxRight) {				//si index i plus grand que son max gauche et droite, ajout à la liste
				maxLocIndices.add(i);
			}	
		}
		
		//Third step : Find the distance that appears the most: it is the most likely key size.

		Map<Integer, Integer> distances = new HashMap<>();
		
		//Keep track of all distances and count them
		for (int i = 0; i < maxLocIndices.size() - 1; i++) {
			int distance = maxLocIndices.get(i + 1) - maxLocIndices.get(i);						//compute the distance between maxLoc
			distances.put(distance, distances.getOrDefault(distance, 0) + 1);					//put the distance in the map and iterate it by one (default to 0 if it doesn't exist
		}
		
		int key_size = 0;
		int distance_count = 0;
		
		
		for (Entry<Integer, Integer> pair : distances.entrySet()) {								//annexe C pour itérer dans les Map
			if (pair.getValue() > distance_count) {
				key_size = pair.getKey();
				distance_count = pair.getValue();
			}
		}
		
		return key_size;
	}

	
	
	/**
	 * Takes the cipher without space, and the key length, and uses the dot product with the English language frequencies 
	 * to compute the shifting for each letter of the key
	 * @param cipher the byte array representing the encoded text without space
	 * @param keyLength the length of the key we want to find
	 * @return the inverse key to decode the Vigenere cipher text
	 */
	public static byte[] vigenereFindKey(List<Byte> cipher, int keyLength) {
		
		List<Byte> key = new ArrayList<Byte>();
		for (int i = 0; i < keyLength; ++i) {
			
			List<Byte> cipher_small = new ArrayList<Byte>();
			for (int j = i; j < cipher.size(); j += keyLength) {
				cipher_small.add(cipher.get(j));
			}
			byte[] cipher_copy = listToByte(cipher_small);
			byte keyOne = caesarWithFrequencies(cipher_copy);
			key.add(keyOne);
		}
		byte[] keyReal = listToByte(key);
		return keyReal;
	}
	
	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method used to decode a String encoded following the CBC pattern
	 * @param cipher the byte array representing the encoded text
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return the clear text
	 */
	public static byte[] decryptCBC(byte[] cipher, byte[] iv) {
		
		byte[] plainText = new byte[cipher.length];
		
		//Decrypt first block using IV
		for (int i = 0; i < iv.length && i < plainText.length; i++) {
			plainText[i] = (byte) (cipher[i] ^ iv[i]);
		}
		
		for (int i = iv.length; i < cipher.length; i += iv.length) {	//decrypt block by block
			for (int j = 0; j < iv.length; j++) {						//index in a block
				if (i + j >= plainText.length) {
					return plainText;
				}
				
				byte b = (byte) (cipher[i + j] ^ cipher[i + j - iv.length]);
				plainText[i + j] = b;
			}
		}

		return plainText;
	}	
	
	//-----------------------Useful small methods-------------------------
	
	//transforms a list in a byte[] array
	public static byte[] listToByte(List<Byte> base) {
		byte[] toReturn = new byte[base.size()];
		for (int i = 0; i < base.size(); ++i) {
			toReturn[i] = base.get(i);
		}
		return toReturn;
	}
}
