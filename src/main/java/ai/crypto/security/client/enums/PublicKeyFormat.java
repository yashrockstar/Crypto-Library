package ai.crypto.security.client.enums;

/**
 * The PublicKeyFormat enum defines the supported formats for public RSA keys.
 * Each enum constant represents a different format, with an associated string
 * that describes the key format. This is particularly useful when handling and
 * converting public keys in various standardized formats.
 */
public enum PublicKeyFormat {

    /*
     * PEM Header: "BEGIN RSA PUBLIC KEY"
     */
    PKCS1("RSAPublicKey"),

    /*
     * certificate
     */
    X509("SubjectPublicKeyInfo"),

    /*
     * Format represented in XML, typically with <RSAKeyValue> element
     */
    XML("XML"),

    /*
     * PEM Header: "BEGIN PUBLIC KEY"
     */
    PEM("PEM"),

    /*
     * public key (not in a certificate)
     */
    Encoded_X509("PEM-encoded X.509");

    private final String keyFormat;

    /**
     * Constructor for the PublicKeyFormat enum.
     *
     * @param keyFormat The string representation of the public key format. This
     *                  representation often aligns with the header used in PEM
     *                  encoding.
     */
    PublicKeyFormat(String keyFormat) {
        this.keyFormat = keyFormat;
    }

    /**
     * Gets the string representation of the public key format.
     *
     * @return The key format as a string. This can be useful for identifying the
     *         format in code or when interfacing with other systems and APIs that
     *         require a specific key format.
     */
    public String getKeyFormat() {
        return keyFormat;
    }
}
