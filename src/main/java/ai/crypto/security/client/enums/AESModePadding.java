package ai.crypto.security.client.enums;

/**
 * Enumeration representing different modes and paddings for the AES (Advanced
 * Encryption Standard) algorithm.
 */
public enum AESModePadding {

	/**
	 * Cipher Block Chaining (CBC) mode with PKCS5 padding.
	 */
	CBC_PKCS5Padding("AES/CBC/PKCS5Padding"),

	/**
	 * Galois/Counter Mode (GCM) with no padding.
	 */
	GCM_NoPadding("AES/GCM/NoPadding"),

	/**
	 * Electronic Codebook (ECB) mode with PKCS5 padding.
	 */
	ECB_PKCS5Padding("AES/ECB/PKCS5Padding"),

	/**
	 * Cipher Block Chaining (CBC) mode with no padding.
	 */
	CBC_NoPadding("AES/CBC/NoPadding"),

	/**
	 * Counter (CTR) mode with no padding.
	 */
	CTR_NoPadding("AES/CTR/NoPadding"),

	/**
	 * Cipher Feedback (CFB) mode with no padding.
	 */
	CFB_NoPadding("AES/CFB/NoPadding"),

	/**
	 * Electronic Codebook (ECB) mode with no padding.
	 */
	ECB_NoPadding("AES/ECB/NoPadding"),

	/**
	 * Output Feedback (OFB) mode with no padding.
	 */
	OFB_NoPadding("AES/OFB/NoPadding"),

	/**
	 * Counter with CBC-MAC (CCM) mode with no padding.
	 */
	CCM_NoPadding("AES/CCM/NoPadding"),

	/**
	 * Cipher Feedback 8 (CFB8) mode with no padding.
	 */
	CFB8_NoPadding("AES/CFB8/NoPadding");

	private final String algorithm;

	/**
	 * Constructs an AESModePadding enum with the specified algorithm.
	 *
	 * @param algorithm The algorithm represented by this enum.
	 */
	AESModePadding(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Gets the algorithm string associated with the AES mode and padding.
	 *
	 * @return The algorithm string.
	 */
	public String getAlgorithm() {
		return algorithm;
	}

}
