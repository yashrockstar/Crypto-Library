package ai.crypto.security.client.enums;

/**
 * Enumeration representing different modes and paddings for the RSA
 * (Rivest–Shamir–Adleman) algorithm.
 */
public enum RSAModePadding {

	/**
	 * RSA with PKCS1 padding in Electronic CodeBook (ECB) mode.
	 */
	ECB_PKCS1Padding("RSA/ECB/PKCS1Padding"),

	/**
	 * RSA in Electronic CodeBook (ECB) mode with no padding.
	 */
	ECB_NoPadding("RSA/ECB/NoPadding"),

	/**
	 * RSA with Optimal Asymmetric Encryption Padding (OAEP) using SHA-256 and MGF1
	 * padding in ECB mode.
	 */
	OAEP_SHA256_MGF1Padding("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),

	/**
	 * RSA with OAEP using SHA-1 and MGF1 padding in ECB mode.
	 */
	OAEP_SHA1_MGF1Padding("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),

	/**
	 * RSA with OAEP using SHA-1 and MGF1 padding in ECB mode with no additional
	 * padding.
	 */
	OAEP_SHA1_NoPadding("RSA/ECB/OAEPWithSHA-1AndMGF1Padding/NoPadding"),

	/**
	 * RSA with OAEP using SHA-256 and MGF1 padding in ECB mode with no additional
	 * padding.
	 */
	OAEP_SHA256_NoPadding("RSA/ECB/OAEPWithSHA-256AndMGF1Padding/NoPadding"),

	/**
	 * RSA with OAEP using SHA-224 and MGF1 padding in ECB mode.
	 */
	OAEP_SHA224_MGF1Padding("RSA/ECB/OAEPWithSHA-224AndMGF1Padding"),

	/**
	 * RSA with OAEP using SHA-512 and MGF1 padding in ECB mode.
	 */
	OAEP_SHA512_MGF1Padding("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

	private final String algorithm;

	/**
	 * Constructs an RSAModePadding enum with the specified algorithm.
	 *
	 * @param algorithm The algorithm represented by this enum.
	 */
	RSAModePadding(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Gets the algorithm string associated with the RSA mode and padding.
	 *
	 * @return The algorithm string.
	 */
	public String getAlgorithm() {
		return algorithm;
	}

}
