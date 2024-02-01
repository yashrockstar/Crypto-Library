package ai.crypto.security.client.enums;

/**
 * Enumeration representing cryptographic algorithms, including AES (Advanced
 * Encryption Standard) and RSA (Rivest–Shamir–Adleman).
 */
public enum CryptographicAlgos {

	/**
	 * Advanced Encryption Standard.
	 */
	AES,

	/**
	 * Rivest–Shamir–Adleman.
	 */
	RSA;

	/**
	 * Gets the string representation of the AES algorithm.
	 *
	 * @return The string representation of AES.
	 */
	public static String getAES() {
		return AES.name();
	}

	/**
	 * Gets the string representation of the RSA algorithm.
	 *
	 * @return The string representation of RSA.
	 */
	public static String getRSA() {
		return RSA.name();
	}
}
