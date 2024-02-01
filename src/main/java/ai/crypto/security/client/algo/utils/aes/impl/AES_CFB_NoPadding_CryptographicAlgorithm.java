package ai.crypto.security.client.algo.utils.aes.impl;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ai.crypto.security.client.algo.utils.CryptographicAlgorithm;
import ai.crypto.security.client.constants.CryptoConstants;
import ai.crypto.security.client.constants.CryptoErrorMessages;
import ai.crypto.security.client.decryption.helper.DecryptionHelper;
import ai.crypto.security.client.encryption.helper.EncryptionHelper;
import ai.crypto.security.client.enums.AESModePadding;
import ai.crypto.security.client.enums.CryptographicAlgos;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.enums.RSAModePadding;
import ai.crypto.security.client.factory.CryptographicFactory;
import ai.crypto.security.client.modal.DecryptedPayload;
import ai.crypto.security.client.modal.EncryptedPayload;
import ai.crypto.security.client.utils.KeyUtils;

/**
 * Implementation of the CryptographicAlgorithm interface for AES encryption
 * with CFB mode and No Padding.
 */
public class AES_CFB_NoPadding_CryptographicAlgorithm implements CryptographicAlgorithm {

	PrivateKeyFormat privateKeyFormat;
	PublicKeyFormat publicKeyFormat;

	/**
	 * Constructor for AES_CFB_NoPadding_CryptographicAlgorithm.
	 *
	 * @param <privateKeyFormat> The format of the private key.
	 * @param <publicKeyFormat>  The format of the public key.
	 */
	public AES_CFB_NoPadding_CryptographicAlgorithm(PrivateKeyFormat privateKeyFormat,
			PublicKeyFormat publicKeyFormat) {
		this.privateKeyFormat = privateKeyFormat;
		this.publicKeyFormat = publicKeyFormat;
	}

	/**
	 * Encrypts the provided data using AES with CFB mode and No Padding.
	 *
	 * @param data The data to be encrypted.
	 * @return <EncryptedPayload> containing the encrypted key and data.
	 * @throws Exception If an error occurs during the encryption process.
	 */
	@Override
	public EncryptedPayload encrypt(String data) throws Exception {
		// Generate a random key for AES encryption
		String skey = KeyUtils.generateKey();
		byte[] key = skey.getBytes();

		CryptographicAlgorithm keyEncryptionAlgorithm = CryptographicFactory.getDataEncryptionAlgorithm(
				CryptographicAlgos.RSA, RSAModePadding.ECB_PKCS1Padding, this.privateKeyFormat, this.publicKeyFormat);

		// Encrypt the AES key using the RSA key encryption algorithm
		String encodedEncryptedKey = keyEncryptionAlgorithm.encrypt(skey).getEncryptedKey();

		// Create a SecretKeySpec using the generated key
		SecretKeySpec secretKey = EncryptionHelper.getSecretKey(key, CryptographicAlgos.getAES());

		// Encrypt the data using AES with CFB mode and No Padding
		IvParameterSpec ivParams = new IvParameterSpec(key);
		Cipher cipher = Cipher.getInstance(AESModePadding.CFB_NoPadding.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
		byte[] encryptedData = cipher.doFinal(data.getBytes());

		// Merge IV and encrypted data
		byte[] mergeIVAndEncryptedData = EncryptionHelper.mergeTwoByteArrays(key, encryptedData);

		// Encode the merged data to base64
		String encodedEncryptedData = EncryptionHelper.encode(mergeIVAndEncryptedData);

		// Create an EncryptedPayload object to store the encrypted key and data
		return new EncryptedPayload(encodedEncryptedKey, encodedEncryptedData);
	}

	/**
	 * Decrypts the provided JSON string containing encrypted key and data using AES
	 * with CFB mode and No Padding.
	 *
	 * @param encryptedString The JSON string containing encrypted key and data.
	 * @return <DecryptedPayload> containing the decrypted key and data.
	 * @throws Exception If an error occurs during the decryption process.
	 */
	@Override
	public DecryptedPayload decrypt(String encryptedString) throws Exception {
		// Parse the JSON string to extract the encrypted key and data
		JsonObject encryptedDataJson = JsonParser.parseString(encryptedString).getAsJsonObject();
		EncryptedPayload encryptedPayload = new Gson().fromJson(encryptedDataJson, EncryptedPayload.class);

		// Check for null or missing components in the encrypted payload
		if (encryptedPayload == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.INVALID_DATA_TO_DECRYPT);
		}
		if (encryptedPayload.getEncryptedKey() == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.INVALID_ENCRYPTED_KEY_TO_DECRYPT);
		}
		if (encryptedPayload.getEncryptedData() == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.INVALID_ENCRYPTED_DATA_TO_DECRYPT);
		}

		// Extract the encrypted key and data from the payload
		String encryptedKey = encryptedPayload.getEncryptedKey();
		String encryptedData = encryptedPayload.getEncryptedData();

		CryptographicAlgorithm keyEncryptionAlgorithm = CryptographicFactory.getDataEncryptionAlgorithm(
				CryptographicAlgos.RSA, RSAModePadding.ECB_PKCS1Padding, this.privateKeyFormat, this.publicKeyFormat);

		// Decrypt the AES key using the RSA key encryption algorithm
		String decodedDecryptedKey = keyEncryptionAlgorithm.decrypt(encryptedKey).getDecryptedKey();

		// Decode the base64-encoded encrypted data
		byte[] decodedEncryptedData = DecryptionHelper.decode(encryptedData);

		// Extract IV and encrypted data
		byte[] iv = DecryptionHelper.extractBytes(decodedEncryptedData, 0, CryptoConstants.KEY_LENGTH);
		byte[] encryptedDataWithoutIV = DecryptionHelper.extractBytes(decodedEncryptedData,
				CryptoConstants.KEY_LENGTH, decodedEncryptedData.length);

		// Create a SecretKeySpec using the decrypted key
		SecretKeySpec secretKey = EncryptionHelper.getSecretKey(decodedDecryptedKey.getBytes(),
				CryptographicAlgos.getAES());

		// Decrypt the data using AES with CFB mode and No Padding
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance(AESModePadding.CFB_NoPadding.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
		byte[] decryptedData = cipher.doFinal(encryptedDataWithoutIV);

		// Create a DecryptedPayload object to store the decrypted key and data
		return new DecryptedPayload(decodedDecryptedKey, new String(decryptedData));
	}
}
