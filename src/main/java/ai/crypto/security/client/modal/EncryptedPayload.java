package ai.crypto.security.client.modal;

/**
 * Represents a payload containing an encrypted key and encrypted data.
 */
public class EncryptedPayload {
	private String encryptedKey;
	private String encryptedData;

	/**
	 * Default constructor for EncryptedPayload.
	 */
	public EncryptedPayload() {
		super();
	}

	/**
	 * Parameterized constructor for EncryptedPayload.
	 *
	 * @param encryptedKey  The encrypted key.
	 * @param encryptedData The encrypted data.
	 */
	public EncryptedPayload(String encryptedKey, String encryptedData) {
		super();
		this.encryptedKey = encryptedKey;
		this.encryptedData = encryptedData;
	}
	
	/**
	 * Parameterized constructor for EncryptedPayload.
	 *
	 * @param encryptedKey The encrypted key.
	 */
	public EncryptedPayload(String encryptedKey) {
		super();
		this.encryptedKey = encryptedKey;
	}

	/**
	 * Gets the encrypted key.
	 *
	 * @return The encrypted key.
	 */
	public String getEncryptedKey() {
		return encryptedKey;
	}

	/**
	 * Sets the encrypted key.
	 *
	 * @param encryptedKey The encrypted key to set.
	 */
	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}

	/**
	 * Gets the encrypted data.
	 *
	 * @return The encrypted data.
	 */
	public String getEncryptedData() {
		return encryptedData;
	}

	/**
	 * Sets the encrypted data.
	 *
	 * @param encryptedData The encrypted data to set.
	 */
	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	/**
	 * Overrides the toString method to provide a string representation of the
	 * EncryptedPayload.
	 *
	 * @return A string representation of the EncryptedPayload.
	 */
	@Override
	public String toString() {
		return "EncryptedPayload [encryptedKey=" + encryptedKey + ", encryptedData=" + encryptedData + "]";
	}
}
