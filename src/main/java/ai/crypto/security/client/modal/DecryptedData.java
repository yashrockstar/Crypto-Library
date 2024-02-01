package ai.crypto.security.client.modal;

/**
 * Represents decrypted data containing event, media, email, and callsid
 * information.
 */
public class DecryptedData {
	private String event;
	private String media;
	private String email;
	private String callsid;

	/**
	 * Default constructor for DecryptedData.
	 */
	public DecryptedData() {
		super();
	}

	/**
	 * Parameterized constructor for DecryptedData.
	 *
	 * @param event   The decrypted event information.
	 * @param media   The decrypted media information.
	 * @param email   The decrypted email information.
	 * @param callsid The decrypted callsid information.
	 */
	public DecryptedData(String event, String media, String email, String callsid) {
		super();
		this.event = event;
		this.media = media;
		this.email = email;
		this.callsid = callsid;
	}

	/**
	 * Gets the decrypted event information.
	 *
	 * @return The decrypted event information.
	 */
	public String getEvent() {
		return event;
	}

	/**
	 * Sets the decrypted event information.
	 *
	 * @param event The decrypted event information to set.
	 */
	public void setEvent(String event) {
		this.event = event;
	}

	/**
	 * Gets the decrypted media information.
	 *
	 * @return The decrypted media information.
	 */
	public String getMedia() {
		return media;
	}

	/**
	 * Sets the decrypted media information.
	 *
	 * @param media The decrypted media information to set.
	 */
	public void setMedia(String media) {
		this.media = media;
	}

	/**
	 * Gets the decrypted email information.
	 *
	 * @return The decrypted email information.
	 */
	public String getEmail() {
		return email;
	}

	/**
	 * Sets the decrypted email information.
	 *
	 * @param email The decrypted email information to set.
	 */
	public void setEmail(String email) {
		this.email = email;
	}

	/**
	 * Gets the decrypted callsid information.
	 *
	 * @return The decrypted callsid information.
	 */
	public String getCallsid() {
		return callsid;
	}

	/**
	 * Sets the decrypted callsid information.
	 *
	 * @param callsid The decrypted callsid information to set.
	 */
	public void setCallsid(String callsid) {
		this.callsid = callsid;
	}
}
