package ai.crypto.security.client.utils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import ai.crypto.security.client.constants.CryptoConstants;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;

/**
 * Utility class for retrieving resources files from the classpath.
 */
public class GetResourcesFiles {

	/**
	 * Retrieves the content of the "PrivateKey" file as a string.
	 *
	 * @return The content of the "PrivateKey" file.
	 */
	public static String getPrivateKeyAsString(PrivateKeyFormat privateKeyFormat) {
		InputStream inputStream = GetResourcesFiles.class.getClassLoader()
				.getResourceAsStream(CryptoConstants.PrivateKey + "_" + privateKeyFormat);
		String privateKey;
		try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
			privateKey = scanner.useDelimiter("\\A").next();
		} catch (Exception e) {
			throw new IllegalArgumentException(CryptoConstants.NO_PrivateKey);
		}
		return privateKey;
	}

	/**
	 * Retrieves the content of the "PublicKey" file as a string.
	 *
	 * @return The content of the "PublicKey" file.
	 */
	public static String getPublicKeyAsString(PublicKeyFormat publicKeyFormat) {
		InputStream inputStream = GetResourcesFiles.class.getClassLoader()
				.getResourceAsStream(CryptoConstants.PublicKey + "_" + publicKeyFormat);
		String publicKey;
		try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
			publicKey = scanner.useDelimiter("\\A").next();
		} catch (Exception e) {
			throw new IllegalArgumentException(CryptoConstants.NO_PublicKey);
		}
		return publicKey;
	}

	/**
	 * Retrieves the "certificate.cer" file as an InputStream.
	 *
	 * @return The InputStream for the "certificate.cer" file.
	 */
	public static InputStream getPublicKeyAsInputStream() {
		return GetResourcesFiles.class.getClassLoader().getResourceAsStream(CryptoConstants.certificate_cer);
	}

	/**
	 * Retrieves the content of the "properties.json" file as a string.
	 *
	 * @return The content of the "properties.json" file.
	 */
	public static String getPrivateKeyPassword(PrivateKeyFormat privateKeyFormat) {
		InputStream inputStream = GetResourcesFiles.class.getClassLoader()
				.getResourceAsStream(CryptoConstants.properties_json + "_" + privateKeyFormat + ".json");
		String properties = null;
		try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
			properties = scanner.useDelimiter("\\A").next();
		} catch (Exception e) {
			throw new IllegalArgumentException(CryptoConstants.NO_PROPERTIES_JSON);
		}
		return properties;
	}
}
