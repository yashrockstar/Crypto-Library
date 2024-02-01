package ai.crypto.security.client.encryption.helper;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Helper class for common encryption operations.
 */
public class EncryptionHelper {

	/**
	 * Encodes a byte array into a Base64-encoded string.
	 *
	 * @param data The byte array to be encoded.
	 * @return The Base64-encoded string.
	 */
	public static String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
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
	 * Generates a PublicKey instance from the provided public key bytes and
	 * encryption mode.
	 *
	 * @param publicKey      The public key bytes.
	 * @param encryptionMode The encryption mode.
	 * @return A PublicKey instance.
	 * @throws NoSuchAlgorithmException If the specified algorithm is not available.
	 * @throws InvalidKeySpecException  If the provided key specification is
	 *                                  invalid.
	 */
	public static PublicKey getPublic(byte[] publicKey, String encryptionMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
		KeyFactory kf = KeyFactory.getInstance(encryptionMode);
		return kf.generatePublic(spec);
	}

	/**
	 * Merges two byte arrays into a single byte array.
	 *
	 * @param arrayOne The first byte array.
	 * @param arrayTwo The second byte array.
	 * @return The merged byte array.
	 */
	public static byte[] mergeTwoByteArrays(byte[] arrayOne, byte[] arrayTwo) {
		byte[] mergedArray = new byte[arrayOne.length + arrayTwo.length];
		System.arraycopy(arrayOne, 0, mergedArray, 0, arrayOne.length);
		System.arraycopy(arrayTwo, 0, mergedArray, arrayOne.length, arrayTwo.length);
		return mergedArray;
	}

	/**
	 * Encrypts content using a secret key, initialization vector (IV), and
	 * encryption algorithm.
	 *
	 * @param content        The content to be encrypted.
	 * @param secretKey      The secret key for encryption.
	 * @param ivParams       The initialization vector parameters.
	 * @param encryptionAlgo The encryption algorithm.
	 * @return The encrypted content.
	 * @throws NoSuchAlgorithmException           If the specified algorithm is not
	 *                                            available.
	 * @throws NoSuchPaddingException             If the padding scheme is not
	 *                                            available.
	 * @throws InvalidKeyException                If the provided key is invalid.
	 * @throws InvalidAlgorithmParameterException If the provided algorithm
	 *                                            parameters are invalid.
	 * @throws IllegalBlockSizeException          If the block size is illegal.
	 * @throws BadPaddingException                If the padding is bad.
	 */
	public static byte[] encrypt(byte[] content, SecretKeySpec secretKey, IvParameterSpec ivParams,
			String encryptionAlgo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(encryptionAlgo);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
		return cipher.doFinal(content);
	}

	/**
	 * Encrypts content using a secret key, algorithm parameters, and encryption
	 * algorithm (GCM mode).
	 *
	 * @param content        The content to be encrypted.
	 * @param secretKey      The secret key for encryption.
	 * @param ivParams       The algorithm parameters.
	 * @param encryptionAlgo The encryption algorithm.
	 * @return The encrypted content.
	 * @throws NoSuchAlgorithmException           If the specified algorithm is not
	 *                                            available.
	 * @throws NoSuchPaddingException             If the padding scheme is not
	 *                                            available.
	 * @throws InvalidKeyException                If the provided key is invalid.
	 * @throws InvalidAlgorithmParameterException If the provided algorithm
	 *                                            parameters are invalid.
	 * @throws IllegalBlockSizeException          If the block size is illegal.
	 * @throws BadPaddingException                If the padding is bad.
	 */
	public static byte[] encryptGCM(byte[] content, SecretKeySpec secretKey, AlgorithmParameterSpec ivParams,
			String encryptionAlgo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(encryptionAlgo);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
		return cipher.doFinal(content);
	}

	/**
	 * Encrypts content using a public key and encryption algorithm.
	 *
	 * @param content        The content to be encrypted.
	 * @param key            The public key for encryption.
	 * @param encryptionAlgo The encryption algorithm.
	 * @return The encrypted content.
	 * @throws NoSuchAlgorithmException  If the specified algorithm is not
	 *                                   available.
	 * @throws NoSuchPaddingException    If the padding scheme is not available.
	 * @throws InvalidKeyException       If the provided key is invalid.
	 * @throws IllegalBlockSizeException If the block size is illegal.
	 * @throws BadPaddingException       If the padding is bad.
	 */
	public static byte[] encrypt(byte[] content, PublicKey key, String encryptionAlgo) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(encryptionAlgo);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(content);
	}
}
