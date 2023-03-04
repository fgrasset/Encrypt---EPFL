package crypto;

import static crypto.Helper.cleanString;
import static crypto.Helper.stringToBytes;
import static crypto.Helper.bytesToString;
import java.util.HashMap;
import java.util.*;

/*
 * Part 1: Encode (with note that one can reuse the functions to decode)
 * Part 2: bruteForceDecode (caesar, xor) and CBCDecode
 * Part 3: frequency analysis and key-length search
 * Bonus: CBC with encryption, shell
 */

public class Main {
	
	
	//---------------------------MAIN---------------------------
	public static void main(String args[]) {
		
		
		String inputMessage = Helper.readStringFromFile("text_one.txt");
		String key = "2cF%5h";
		
		String messageClean = cleanString(inputMessage);
		
		
		byte[] messageBytes = stringToBytes(messageClean);
		byte[] keyBytes = stringToBytes(key);

		
		System.out.println("Original input sanitized : " + messageClean);
		System.out.println();
		
		System.out.println("------Caesar------");
	    testCaesar(messageBytes, keyBytes[0]);
	    
	    System.out.println();
	    System.out.println("------Xor------");
	    testXor(messageBytes, keyBytes[0]);
	    
	    System.out.println();
	    System.out.println("------CBC------");
	    testCBC(messageBytes);
	    
	    System.out.println();
	    System.out.println("------OTP------");
	    testOTP(messageBytes);
	    
	    System.out.println();
	    System.out.println("------Vigenere------");
	    testVigenere(messageBytes, keyBytes);
	    
	    //Test Challenge
	    byte[] cipherText = Helper.readBytesFromFile("challenge-encrypted.bin");

	    byte[] plainTextBytes = Decrypt.vigenereWithFrequencies(cipherText);
	    String s3 = bytesToString(plainTextBytes);
	    System.out.println("Challenge : " + s3);
	    System.out.println();

	    System.out.println("------encrypt & breakCipher------");
	    
	    //Test encrypt
	    System.out.println("Encrypt : " + Encrypt.encrypt(messageClean, key, 4));
	    
	    //Test breakCipher
	    System.out.println();
	    System.out.println("BreakCipher : " + Decrypt.breakCipher(messageClean, 1));
	    
	    //test de Map
//	    Map<Integer, Integer> test = new HashMap<>();
//	    
//	    test.put(3, 5);
//	    test.put(2, (test.get(2) + 1));
//	    System.out.println("test getkey : " + test.get(2));
	    

	}
	
	
	//Run the Encoding and Decoding using the caesar pattern 
	public static void testCaesar(byte[] string , byte key) {
		
		//Encoding
		byte[] result = Encrypt.caesar(string, key);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);
		
		
		//Decoding with key
		String sD = bytesToString(Encrypt.caesar(result, (byte) (-key)));
		System.out.println("Decoded knowing the key : " + sD);
		
		//Decoding without key
		byte[][] bruteForceResult = Decrypt.caesarBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceCaesar.txt");
		System.out.println("BruteForce : Verifier manuellement dans le .txt");
		
		byte decodingKey = Decrypt.caesarWithFrequencies(result);
		String sFD = bytesToString(Encrypt.caesar(result, decodingKey));
		System.out.println("Decoded without knowing the key : " + sFD);
	}
	
	
	//Run the Encoding and Decoding using the XOR pattern
	public static void testXor(byte[] string, byte key) {
		
		//Encoding
		byte[] result = Encrypt.xor(string, key);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);
		
		//Decoding without key
		byte[][] bruteForceResult = Decrypt.xorBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceXor.txt");
		System.out.println("Brute Force : Verifier manuellement dans le .txt");
		
		//Decoding with key
		byte[] plainText = Encrypt.xor(result, key);
		String s2 = bytesToString(plainText);
		System.out.println("Decoded : " + s2);
		
	}
	
	
	//Run the Encoding and Decoding using the CBC pattern
	public static void testCBC(byte[] messageBytes) {
		
		//Encoding
		byte[] iv = Encrypt.generatePad(4);
		System.out.print("Using IV : ");
		for (int i = 0; i < iv.length; i++) {
			System.out.print(iv[i] + " ");
		}
		
		System.out.println();
		byte[] cipherText = Encrypt.cbc(messageBytes, iv);
		System.out.print("Encoded : " + bytesToString(cipherText));
		
		//Decoding
		System.out.println();
		byte[] decryptedBytes = Decrypt.decryptCBC(cipherText, iv);
		String decryptedPlainText = bytesToString(decryptedBytes);
		System.out.println("Decoded : " + decryptedPlainText);
	}
	
	
	//Run the Encoding using the One-Time-Pad pattern
	public static void testOTP(byte[] messageBytes) {
		
		//Encoding
		byte[] iv = Encrypt.generatePad(messageBytes.length);
		System.out.print("Using IV : ");
		for (int i = 0; i < iv.length; i++) {
			System.out.print(iv[i] + " ");
		}
		System.out.println();
		
		byte[] cipherText = Encrypt.oneTimePad(messageBytes, iv);
		System.out.print("Encoded : " + bytesToString(cipherText));
		System.out.println();
		
	}
	
	//Run the Encoding and Decoding using the Vigenere pattern
	public static void testVigenere(byte[] messageBytes, byte[] keyBytes) {
		
		//Encoding
		byte[] result = Encrypt.vigenere(messageBytes, keyBytes);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);
		
		//Decoding
		byte[] plainText = Decrypt.vigenereWithFrequencies(result);
		String s2 = bytesToString(plainText);
		System.out.println("Decoded : " + s2);
		
		
		
		
	}
	
	
	
	
	
	
	
}
