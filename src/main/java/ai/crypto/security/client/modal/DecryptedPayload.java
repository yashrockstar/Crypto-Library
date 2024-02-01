package ai.crypto.security.client.modal;

/**
 * Represents a payload containing a decrypted key and associated decrypted
 * data.
 */
public class DecryptedPayload {
	private String decryptedKey;
	private String decryptedData;

	/**
	 * Default constructor for DecryptedPayload.
	 */
	public DecryptedPayload() {
		super();
	}

	/**
	 * Parameterized constructor for DecryptedPayload.
	 *
	 * @param decryptedKey  The decrypted key.
	 * @param decryptedData The associated decrypted data.
	 */
	public DecryptedPayload(String decryptedKey, String decryptedData) {
		super();
		this.decryptedKey = decryptedKey;
		this.decryptedData = decryptedData;
	}
	
	/**
	 * Parameterized constructor for DecryptedPayload.
	 *
	 * @param decryptedData The associated decrypted data.
	 */
	public DecryptedPayload(String decryptedKey) {
		super();
		this.decryptedKey = decryptedKey;
	}

	/**
	 * Gets the decrypted key.
	 *
	 * @return The decrypted key.
	 */
	public String getDecryptedKey() {
		return decryptedKey;
	}

	/**
	 * Sets the decrypted key.
	 *
	 * @param decryptedKey The decrypted key to set.
	 */
	public void setDecryptedKey(String decryptedKey) {
		this.decryptedKey = decryptedKey;
	}

	/**
	 * Gets the associated decrypted data.
	 *
	 * @return The associated decrypted data.
	 */
	public String getDecryptedData() {
		return decryptedData;
	}

	/**
	 * Sets the associated decrypted data.
	 *
	 * @param decryptedData The associated decrypted data to set.
	 */
	public void setDecryptedData(String decryptedData) {
		this.decryptedData = decryptedData;
	}

	/**
	 * Overrides the toString method to provide a string representation of the
	 * DecryptedPayload.
	 *
	 * @return A string representation of the DecryptedPayload.
	 */
	@Override
	public String toString() {
		return "DecryptedPayload [decryptedKey=" + decryptedKey + ", decryptedData=" + decryptedData + "]";
	}
}
