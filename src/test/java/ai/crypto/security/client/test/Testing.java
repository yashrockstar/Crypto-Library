package ai.crypto.security.client.test;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ai.crypto.security.client.algo.utils.CryptographicAlgorithm;
import ai.crypto.security.client.enums.AESModePadding;
import ai.crypto.security.client.enums.CryptographicAlgos;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.modal.DecryptedPayload;
import ai.crypto.security.client.modal.EncryptedPayload;
import ai.crypto.security.client.security.CryptoSecurityService;

/**
 * A class for testing cryptographic algorithms.
 */
public class Testing {

	/**
	 * The main method to initiate testing of cryptographic algorithms.
	 *
	 * @param args Command-line arguments.
	 */
	public static void main(String[] args) {

		// Create a JSON object for testing
		JsonObject json = new JsonObject();
		json.addProperty("event", "start");
		json.addProperty("media", "None");
		json.addProperty("callsid", "247a4d14-a267-423a-869e-89defed528ff");
		json.addProperty("email", "aditya52@crypto.ai");

		String data = "Hello World!!";

		// Test AES with CBC_PKCS5Padding
		try {
			AES_CBC_PKCS5Padding(data);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Test method for AES with CBC_PKCS5Padding.
	 *
	 * @param data The data to be encrypted and decrypted.
	 * @throws Exception If an error occurs during encryption or decryption.
	 */
	public static void AES_CBC_PKCS5Padding(String data) throws Exception {
		CryptographicAlgorithm init = CryptoSecurityService.init(CryptographicAlgos.AES,
				AESModePadding.CBC_PKCS5Padding, PrivateKeyFormat.PKCS8, PublicKeyFormat.PEM);

		System.err.println("AES/ECB/PKCS5Padding");

		// Encrypt and print
		EncryptedPayload encryptedPayload = init.encrypt(data);
		String encryptpkcs1 = new Gson().toJson(encryptedPayload);
		System.out.println(encryptpkcs1);

		// Decrypt and print
		DecryptedPayload decryptpkcs1 = init.decrypt(encryptpkcs1);
		System.out.println(new Gson().newBuilder().setPrettyPrinting().create().toJson(decryptpkcs1));
		Thread.sleep(1000);
	}

}
