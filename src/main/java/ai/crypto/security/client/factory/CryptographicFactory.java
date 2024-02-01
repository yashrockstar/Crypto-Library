package ai.crypto.security.client.factory;

import ai.crypto.security.client.algo.utils.CryptographicAlgorithm;
import ai.crypto.security.client.algo.utils.aes.impl.*;
import ai.crypto.security.client.algo.utils.rsa.impl.*;
import ai.crypto.security.client.constants.CryptoErrorMessages;
import ai.crypto.security.client.enums.AESModePadding;
import ai.crypto.security.client.enums.CryptographicAlgos;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.enums.RSAModePadding;

/**
 * Factory class for creating instances of CryptographicAlgorithm based on
 * specified parameters.
 */
public class CryptographicFactory {

	/**
	 * Creates and returns a CryptographicAlgorithm based on the specified
	 * parameters.
	 *
	 * @param algorithm        The cryptographic algorithm to initialize.
	 * @param modePadding      The mode and padding to use for the algorithm.
	 * @param privateKeyFormat The format of the private key.
	 * @param publicKeyFormat  The format of the public key.
	 * @param <T>              The type of Enum for mode and padding.
	 * @return An instance of CryptographicAlgorithm initialized with the specified
	 *         parameters.
	 * @throws IllegalArgumentException If any of the input parameters is null or if
	 *                                  an unsupported combination is provided.
	 */
	public static <T extends Enum<T>> CryptographicAlgorithm getDataEncryptionAlgorithm(CryptographicAlgos algorithm,
			T modePadding, PrivateKeyFormat privateKeyFormat, PublicKeyFormat publicKeyFormat) {
		
		switch (algorithm) {
		case AES:
			if (modePadding instanceof AESModePadding) {
				switch ((AESModePadding) modePadding) {
				case CBC_PKCS5Padding:
					return new AES_CBC_PKCS5Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case GCM_NoPadding:
					return new AES_GCM_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case ECB_PKCS5Padding:
					return new AES_ECB_PKCS5Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case CBC_NoPadding:
					return new AES_CBC_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case CTR_NoPadding:
					return new AES_CTR_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case CFB_NoPadding:
					return new AES_CFB_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case ECB_NoPadding:
					return new AES_ECB_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OFB_NoPadding:
					return new AES_OFB_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case CCM_NoPadding:
					return new AES_CCM_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case CFB8_NoPadding:
					return new AES_CFB8_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				default:
					throw new IllegalArgumentException(
							CryptoErrorMessages.UNSUPPORTED_AES_MODE_PADDING + modePadding);
				}
			} else {
				throw new IllegalArgumentException(CryptoErrorMessages.UNSUPPORTED_COMBINATION_OF_MODEPADDING
						+ modePadding + " with " + CryptographicAlgos.AES + " cryptographic algorithm");
			}
		case RSA:
			if (modePadding instanceof RSAModePadding) {
				switch ((RSAModePadding) modePadding) {
				case ECB_PKCS1Padding:
					return new RSA_ECB_PKCS1Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case ECB_NoPadding:
					return new RSA_ECB_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OAEP_SHA256_MGF1Padding:
					return new RSA_OAEP_SHA256_MGF1Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OAEP_SHA1_MGF1Padding:
					return new RSA_OAEP_SHA1_MGF1Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OAEP_SHA1_NoPadding:
					return new RSA_OAEP_SHA1_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OAEP_SHA256_NoPadding:
					return new RSA_OAEP_SHA256_NoPadding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OAEP_SHA224_MGF1Padding:
					return new RSA_OAEP_SHA224_MGF1Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				case OAEP_SHA512_MGF1Padding:
					return new RSA_OAEP_SHA512_MGF1Padding_CryptographicAlgorithm(privateKeyFormat, publicKeyFormat);
				default:
					throw new IllegalArgumentException(
							CryptoErrorMessages.UNSUPPORTED_RSA_MODE_PADDING + modePadding);
				}
			} else {
				throw new IllegalArgumentException(CryptoErrorMessages.UNSUPPORTED_COMBINATION_OF_MODEPADDING
						+ modePadding + " with " + CryptographicAlgos.RSA + " cryptographic algorithm");
			}
		default:
			throw new IllegalArgumentException(CryptoErrorMessages.UNSUPPORTED_CRYPTOGRAPHIC_ALGORITHM + algorithm);
		}
	}
}
