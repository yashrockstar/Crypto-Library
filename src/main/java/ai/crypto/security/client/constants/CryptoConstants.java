package ai.crypto.security.client.constants;

/**
 * Constants used in the crypto client application.
 */
public class CryptoConstants {

	/**
	 * The alphanumeric characters used for generating keys. This string contains
	 * digits and both lowercase and uppercase letters, which are often used in key
	 * generation algorithms for enhanced security.
	 */
	public static final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	/**
	 * The length of the encryption key. This specifies the size of the key in
	 * characters, used in encryption algorithms. A length of 16 is a common choice
	 * for certain types of encryption keys.
	 */
	public static final int KEY_LENGTH = 16;

	/**
	 * The password constant. This is a placeholder for demonstration purposes and
	 * should be replaced with an actual secure password in production environments
	 * for the encrypted private keys.
	 */
	public static final String password = "password";

	/**
	 * The X.509 certificate format constant. X.509 is a standard defining the
	 * format of public key certificates, used in various security and encryption
	 * protocols.
	 */
	public static final String X_509 = "X.509";

	/**
	 * The RSA encryption algorithm constant. RSA is a widely used public-key
	 * cryptographic algorithm.
	 */
	public static final String RSA = "RSA";

	/**
	 * The PKCS12 constant. PKCS12 is a standard for storing a private key and a
	 * certificate in a secure, encrypted file format, often used for transporting
	 * and storing keys and certificates.
	 */
	public static final String PKCS12 = "PKCS12";

	/**
	 * The PrivateKey constant. This is used to refer to private keys within
	 * cryptographic operations.
	 */
	public static final String PrivateKey = "PrivateKey";

	/**
	 * The PublicKey constant. This is used to refer to public keys in cryptographic
	 * operations.
	 */
	public static final String PublicKey = "PublicKey";

	/**
	 * The certificate file name constant. 'certificate.cer' is a common filename
	 * for X.509 certificates.
	 */
	public static final String certificate_cer = "certificate.cer";

	/**
	 * The properties file name constant. 'properties.json' is typically used to
	 * store configuration properties in JSON format.
	 */
	public static final String properties_json = "properties";

	/**
	 * Header for PKCS1 private keys.
	 */
	public static final String PKCS1_private_header = "BEGIN RSA PRIVATE KEY";

	/**
	 * Header for PKCS8 private keys.
	 */
	public static final String PKCS8_header = "BEGIN PRIVATE KEY";

	/**
	 * Header for encrypted PKCS8 private keys.
	 */
	public static final String Encrypted_PKCS8_header = "BEGIN ENCRYPTED PRIVATE KEY";

	/**
	 * Header for XML-formatted keys.
	 */
	public static final String XML_header = "<RSAKeyValue>";

	/**
	 * Header for JWK-formatted keys.
	 */
	public static final String JWK_header = "{";

	/**
	 * Header for PKCS1 public keys.
	 */
	public static final String PKCS1_public_header = "BEGIN RSA PUBLIC KEY";

	/**
	 * Header for PEM-formatted keys.
	 */
	public static final String PEM_header = "BEGIN PUBLIC KEY";

	/**
	 * Header for X.509 encoded certificates.
	 */
	public static final String Encoded_X509_header = "-----BEGIN CERTIFICATE-----";

	/**
	 * Error message indicating that the value for the password key in the
	 * properties.json file is invalid.
	 */
	public static final String PASSWORD_FOR_ENCRYPYED_KEY_IS_INVALID = "The value for password key in properties.json file is invalid !!!";

	/**
	 * Error message indicating that no password key is provided in the
	 * properties.json file.
	 */
	public static final String NO_PASSWORD_FOR_ENCRYPYED_KEY_IS_PROVIDED = "No password key in properties.json file";

	/**
	 * Error message indicating that the properties.json file is required in the
	 * resources folder.
	 */
	public static final String NO_PROPERTIES_JSON = "Required properties.json file in the resources folder";

	/**
	 * Error message indicating that the PrivateKey file is required in the
	 * resources folder.
	 */
	public static final String NO_PrivateKey = "Required PrivateKey file in the resources folder";

	/**
	 * Error message indicating that the PublicKey file is required in the resources
	 * folder.
	 */
	public static final String NO_PublicKey = "Required PublicKey file in the resources folder";

	/**
	 * Error message indicating that the certificate.cer file is required in the
	 * resources folder.
	 */
	public static final String NO_CERTIFICATE = "Required certificate.cer file in the resources folder";

}
