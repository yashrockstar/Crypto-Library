package ai.crypto.security.client.security;

import ai.crypto.security.client.algo.utils.CryptographicAlgorithm;
import ai.crypto.security.client.constants.CryptoErrorMessages;
import ai.crypto.security.client.enums.CryptographicAlgos;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.factory.CryptographicFactory;

/**
 * Service class for crypto Security, providing methods for initializing
 * cryptographic algorithms.
 */
public class CryptoSecurityService {

	/**
	 * Initializes a cryptographic algorithm based on the specified parameters.
	 *
	 * @param algorithm        The cryptographic algorithm to initialize.
	 * @param modePadding      The mode and padding to use for the algorithm.
	 * @param privateKeyFormat The format of the private key.
	 * @param publicKeyFormat  The format of the public key.
	 * @param <T>              The type of Enum for mode and padding.
	 * @return An instance of CryptographicAlgorithm initialized with the specified
	 *         parameters.
	 * @throws IllegalArgumentException If any of the input parameters is null.
	 */
	public static <T extends Enum<T>> CryptographicAlgorithm init(CryptographicAlgos algorithm, T modePadding,
			PrivateKeyFormat privateKeyFormat, PublicKeyFormat publicKeyFormat) {

		// Check if the cryptographic algorithm is provided
		if (algorithm == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.NULL_ALGORITHM);
		}

		// Check if the mode and padding information is provided
		if (modePadding == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.NULL_MODE_PADDING);
		}

		// Check if the publicKeyFormat information is provided
		if (privateKeyFormat == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.NULL_PRIVATE_KEY);
		}

		// Check if the publicKeyFormat information is provided
		if (publicKeyFormat == null) {
			throw new IllegalArgumentException(CryptoErrorMessages.NULL_PUBLIC_KEY);
		}

		// Initialize and return the CryptographicAlgorithm using the provided
		// parameters
		return CryptographicFactory.getDataEncryptionAlgorithm(algorithm, modePadding, privateKeyFormat,
				publicKeyFormat);
	}
}
