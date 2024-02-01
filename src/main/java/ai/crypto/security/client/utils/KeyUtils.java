package ai.crypto.security.client.utils;

import java.security.SecureRandom;

import ai.crypto.security.client.constants.CryptoConstants;

/**
 * Utility class for generating cryptographic keys.
 */
public class KeyUtils {

	/**
	 * Generates a random cryptographic key using the characters from
	 * CryptoConstants.AB.
	 *
	 * @return The generated key as a string.
	 */
	public static String generateKey() {
		SecureRandom rnd = new SecureRandom();
		StringBuilder sb = new StringBuilder(CryptoConstants.KEY_LENGTH);
		for (int i = 0; i < CryptoConstants.KEY_LENGTH; i++) {
			sb.append(CryptoConstants.AB.charAt(rnd.nextInt(CryptoConstants.AB.length())));
		}
		return sb.toString();
	}
}
