package ai.crypto.security.client.algo.utils;

import ai.crypto.security.client.modal.DecryptedPayload;
import ai.crypto.security.client.modal.EncryptedPayload;

/**
 * Interface representing a Cryptographic Algorithm for encryption and
 * decryption operations.
 */
public interface CryptographicAlgorithm {
	
	/**
	 * Encrypts the provided data using the specific cryptographic algorithm.
	 *
	 * @param data The data to be encrypted.
	 * @return The EncryptedPayload with the encrypted key and encrypted data.
	 * @throws Exception If an error occurs during the encryption process.
	 */
	EncryptedPayload encrypt(String data) throws Exception;

	/**
	 * Decrypts the provided data using the specific cryptographic algorithm.
	 *
	 * @param data The data to be decrypted.
	 * @return The DecryptedPayload with the decrypted key and decrypted data.
	 * @throws Exception If an error occurs during the decryption process.
	 */
	DecryptedPayload decrypt(String data) throws Exception;
}
