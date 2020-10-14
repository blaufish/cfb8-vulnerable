package org.blaufish.cfb8vulnerable;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * "Netlogon CFB8 considered harmful" NakedSecurity, 2020-09-17.
 *
 * Demo of the vulnerability described in the article.
 *
 * Test for ZeroLogon behavior in which CFB-8 goes into an incredibly interesting and exploitable behavior
 * when IV = 0 and P = 0.
 *
 * Some keys will trigger the all-zero S states, some will not (1/256 chance that it will).
 *
 * (CFB-8 appears to be quite broken and dangerous as the IV-bytes are reused 15 times,
 * i.e. plaintext and IV are reused a lot. And 128-bit cipher is reduced to an 8-bit PRF,
 * throwing away some of the benefits of a large block cipher. This bug was a Microsoft
 * implementation error, but it seems to demonstrate the underlying weirdness of the CFB8
 * mode)
 *
 * OFB8 is vulnerable to same hang on IV=0, and would in fact decode any OFB.
 *
 * https://nakedsecurity.sophos.com/2020/09/17/zerologon-hacking-windows-servers-with-a-bunch-of-zeros/
 *
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
 *
 */
public class CFB8Vulnerable {

	/**
     *
     * CFB8, OFB8 IV=0 P=0 vulnerability demo
     *
     * Algorithm traverses 8 bits at a time, performs one AES operation per 8 bits.
     *
     * Algorithm breaks completely for 1/256 of keys, stalling on internal state S stuck at all-zero forever.
     *
     * Algorithms vulnerable:
     *
     * CFB8:
     * S0 = IV
     * Ci = head8( E( Si-1 ) ) xor Pi
     * Si = (S << 8 + Ci)
     *
     * OFB8:
     * S0 = IV
     * Oi = head8( E( Si-1 ) )
     * Ci = Oi xor Pi
     * Si = (S << 8 + Oi)
     *
	 * @param secretKey a random AES key. 
	 * @return true if all zero ciphertext detected in the end
	 * @throws Exception Because Java...
	 */
	public static boolean ofb8_cfb8_iv0_plaintext0(SecretKey secretKey, boolean testOFB8) throws Exception {
		byte[] plaintext = new byte[8];
		byte[] ciphertext = new byte[plaintext.length];
		byte[] s = new byte[16]; // IV all zeros = vulnerable!

		for (int i = 0; i < plaintext.length; i++) {
			byte[] intermediateCipherBlock = AES_ECB(secretKey, s);
			byte output8 = intermediateCipherBlock[0]; // Throw away 15 out of 16 bytes...
			System.out.printf("%s: i=%d s=%s intermediate=AES(s)=%s c=%02x\n", testOFB8 ? "OFB-8" : "CFB-8", i,
					bytesToHex(s), bytesToHex(intermediateCipherBlock), output8);
			ciphertext[i] = (byte) (plaintext[i] ^ output8);

			byte lsb = testOFB8 ? output8 : ciphertext[i];
			shift8(s, lsb);
		}

		return failIfAllZero(ciphertext);
	}

	private static void shift8(byte[] s, byte lsb) {
		System.arraycopy(s, 1, s, 0, s.length-1);
		s[s.length-1] = lsb;
	}

	public static void main(String[] args) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example

		for (int i = 0; i < 2; i++) {
			boolean testOFB = (i == 1);

			int counter = 0;
			while (true) {
				counter++;
				SecretKey secretKey = keyGen.generateKey();
				System.out.printf("Key = %s\n", bytesToHex(secretKey.getEncoded()));
				if (ofb8_cfb8_iv0_plaintext0(secretKey, testOFB)) {
					if (testOFB)
						System.out.printf(
								"OFB8 attack also vulnerable to same sample - after testing %d keys, with IV=0, P=0 on a random key, C=0 due to S stuck at S=0\n",
								counter);
					else
						System.out.printf(
								"Netlogon CFB8 considered harmful vulnerability found - after testing %d keys, with IV=0, P=0 on a random key, C=0 due to S stuck at S=0\n",
								counter);
					break;
				}
			}
		}
		System.out.println("Both OFB8 and CFB8 broken on IV=0 P=0");
	}

	//https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
	public static String bytesToHex(byte[] bytes) {
	    byte[] hexChars = new byte[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars, StandardCharsets.UTF_8);
	}
	
	public static byte[] AES_ECB(SecretKey secretKey, byte[] plaintext) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(plaintext);
	}

	private static boolean failIfAllZero(byte[] ciphertext) {
		boolean zero;
		zero = true;
		for (int i = 0; i < ciphertext.length; i++)
			if (ciphertext[i] != 0)
				zero = false;
		return zero;
	}
}
