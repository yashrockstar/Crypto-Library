package ai.crypto.security.client.enums;

/**
 * The PrivateKeyFormat enum defines the supported formats for private keys.
 * Each enum constant represents a different format, with an associated string
 * that describes the key format. This is particularly useful when handling and
 * converting private keys in various standardized formats.
 */
public enum PrivateKeyFormat {
	/**
	 * Represents an encrypted private key in PKCS#8 format. PEM Header: "BEGIN
	 * ENCRYPTED PRIVATE KEY"
	 */
	Encrypted_PKCS8("EncryptedPrivateKeyInfo"),

	/**
	 * Represents a private key typically in PKCS#12 (PFX) format. This is often
	 * used in scenarios where the key is bundled with a certificate.
	 */
	PKCS12("PKCS8ShroudedKeyBag"),

	/**
	 * Represents a private key in PKCS#1 format. PEM Header: "BEGIN RSA PRIVATE
	 * KEY"
	 */
	PKCS1("RSAPrivateKey"),

	/**
	 * Represents a private key in unencrypted PKCS#8 format. PEM Header: "BEGIN
	 * PRIVATE KEY"
	 */
	PKCS8("PrivateKeyInfo"),

	/**
	 * Represents a private key in XML format. Typically formatted with an
	 * <RSAKeyValue> element.
	 */
	XML("XML"),

	/**
	 * Represents a private key in JSON Web Key (JWK) format. Key Type: "RSA"
	 */
	JWK("JWK");

	private final String keyFormat;

	/**
	 * Constructor for the PrivateKeyFormat enum.
	 *
	 * @param keyFormat The string representation of the private key format. This
	 *                  representation can align with headers used in PEM encoding
	 *                  or other format specifications.
	 */
	PrivateKeyFormat(String keyFormat) {
		this.keyFormat = keyFormat;
	}

	/**
	 * Gets the string representation of the private key format.
	 *
	 * @return The key format as a string. This can be useful for identifying the
	 *         format in code or when interfacing with other systems and APIs that
	 *         require a specific key format.
	 */
	public String getKeyFormat() {
		return keyFormat;
	}
}
