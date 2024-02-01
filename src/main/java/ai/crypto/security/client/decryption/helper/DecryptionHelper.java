package ai.crypto.security.client.decryption.helper;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Helper class for common decryption operations.
 */
public class DecryptionHelper {

	/**
	 * Decodes a Base64-encoded string into a byte array.
	 *
	 * @param data The Base64-encoded string.
	 * @return The decoded byte array.
	 */
	public static byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}

	/**
	 * Creates a SecretKeySpec instance using the provided key bytes and algorithm.
	 *
	 * @param keyBytes  The key bytes.
	 * @param algorithm The encryption algorithm.
	 * @return A SecretKeySpec instance.
	 */
	public static SecretKeySpec getSecretKey(byte[] keyBytes, String algorithm) {
		return new SecretKeySpec(keyBytes, algorithm);
	}

	/**
	 * Generates a PrivateKey instance from the provided private key bytes and
	 * decryption mode.
	 *
	 * @param privateKey     The private key bytes.
	 * @param decryptionMode The decryption mode.
	 * @return A PrivateKey instance.
	 * @throws NoSuchAlgorithmException If the specified algorithm is not available.
	 * @throws InvalidKeySpecException  If the provided key specification is
	 *                                  invalid.
	 */
	public static PrivateKey getPrivate(byte[] privateKey, String decryptionMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory kf = KeyFactory.getInstance(decryptionMode);
		return kf.generatePrivate(spec);
	}

	/**
	 * Extracts a subarray of bytes from the input array.
	 *
	 * @param input      The input byte array.
	 * @param startIndex The starting index.
	 * @param endIndex   The ending index.
	 * @return The extracted byte array.
	 */
	public static byte[] extractBytes(byte[] input, int startIndex, int endIndex) {
		return Arrays.copyOfRange(input, startIndex, endIndex);
	}

	/**
	 * Decrypts content using a secret key, initialization vector (IV), and
	 * decryption algorithm.
	 *
	 * @param encryptedContent The content to be decrypted.
	 * @param secretKey        The secret key for decryption.
	 * @param iv               The initialization vector.
	 * @param decryptionAlgo   The decryption algorithm.
	 * @return The decrypted content.
	 * @throws InvalidKeyException                If the provided key is invalid.
	 * @throws IllegalBlockSizeException          If the block size is illegal.
	 * @throws BadPaddingException                If the padding is bad.
	 * @throws NoSuchAlgorithmException           If the specified algorithm is not
	 *                                            available.
	 * @throws NoSuchPaddingException             If the padding scheme is not
	 *                                            available.
	 * @throws InvalidAlgorithmParameterException If the provided algorithm
	 *                                            parameters are invalid.
	 */
	public static byte[] decrypt(byte[] encryptedContent, SecretKeySpec secretKey, byte[] iv, String decryptionAlgo)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(decryptionAlgo);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
		return cipher.doFinal(encryptedContent);
	}

	/**
	 * Decrypts content using a secret key, algorithm parameters, and decryption
	 * algorithm (GCM mode).
	 *
	 * @param encryptedContent The content to be decrypted.
	 * @param secretKey        The secret key for decryption.
	 * @param iv               The initialization vector.
	 * @param decryptionAlgo   The decryption algorithm.
	 * @return The decrypted content.
	 * @throws InvalidKeyException                If the provided key is invalid.
	 * @throws IllegalBlockSizeException          If the block size is illegal.
	 * @throws BadPaddingException                If the padding is bad.
	 * @throws NoSuchAlgorithmException           If the specified algorithm is not
	 *                                            available.
	 * @throws NoSuchPaddingException             If the padding scheme is not
	 *                                            available.
	 * @throws InvalidAlgorithmParameterException If the provided algorithm
	 *                                            parameters are invalid.
	 */
	public static byte[] decryptGCM(byte[] encryptedContent, SecretKeySpec secretKey, byte[] iv, String decryptionAlgo)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(decryptionAlgo);
		GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
		return cipher.doFinal(encryptedContent);
	}

	/**
	 * Decrypts content using a private key and decryption algorithm.
	 *
	 * @param content        The content to be decrypted.
	 * @param key            The private key for decryption.
	 * @param decryptionAlgo The decryption algorithm.
	 * @return The decrypted content.
	 * @throws NoSuchAlgorithmException  If the specified algorithm is not
	 *                                   available.
	 * @throws NoSuchPaddingException    If the padding scheme is not available.
	 * @throws InvalidKeyException       If the provided key is invalid.
	 * @throws IllegalBlockSizeException If the block size is illegal.
	 * @throws BadPaddingException       If the padding is bad.
	 */
	public static byte[] decrypt(byte[] content, PrivateKey key, String decryptionAlgo) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(decryptionAlgo);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(content);
	}
}
