package ai.crypto.security.client.certificate.utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ai.crypto.security.client.constants.CryptoConstants;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.utils.GetResourcesFiles;

/**
 * The `PrivateKeyUtils` class provides utility methods for detecting and
 * converting private keys in various formats such as PKCS1, PKCS8, Encrypted
 * PKCS8, XML, PKCS12, and JWK.
 */
public class PrivateKeyUtils {

	/**
	 * Detects the format of the private key based on its content.
	 *
	 * @return The detected private key format.
	 * @throws IllegalArgumentException If the private key format is unknown or
	 *                                  unsupported.
	 */
	public static PrivateKeyFormat detectPrivateKeyFormat() {
		try (InputStream is = CertUtils.class.getClassLoader().getResourceAsStream(CryptoConstants.PrivateKey);
				BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.contains(CryptoConstants.PKCS1_private_header)) {
					return PrivateKeyFormat.PKCS1;
				} else if (line.contains(CryptoConstants.PKCS8_header)) {
					return PrivateKeyFormat.PKCS8;
				} else if (line.contains(CryptoConstants.Encrypted_PKCS8_header)) {
					return PrivateKeyFormat.Encrypted_PKCS8;
				} else if (line.contains(CryptoConstants.XML_header)) {
					return PrivateKeyFormat.XML;
				} else if (line.startsWith(CryptoConstants.JWK_header)) {
					return PrivateKeyFormat.JWK;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new IllegalArgumentException("Unknown or unsupported private key format");
	}

	/**
	 * Converts an encrypted PKCS8 private key to a PrivateKey object.
	 *
	 * @return The decrypted PrivateKey object.
	 */
	protected static PrivateKey convertEncrypted_PKCS8ToPrivateKey() {
		try {
			String encryptedPrivateKey = GetResourcesFiles.getPrivateKeyAsString(PrivateKeyFormat.Encrypted_PKCS8);

			String privateKeyPassword = GetResourcesFiles.getPrivateKeyPassword(PrivateKeyFormat.Encrypted_PKCS8);

			if (privateKeyPassword != null) {

				JsonObject asJsonObject = JsonParser.parseString(privateKeyPassword).getAsJsonObject();

				if (asJsonObject.has(CryptoConstants.password)) {
					if (!asJsonObject.get(CryptoConstants.password).isJsonNull()
							&& asJsonObject.get(CryptoConstants.password) != null
							&& asJsonObject.get(CryptoConstants.password).getAsString() != "null") {

						String password = asJsonObject.get(CryptoConstants.password).getAsString();

						EncryptedPrivateKeyInfo pkInfo = new EncryptedPrivateKeyInfo(
								Base64.getDecoder().decode(encryptedPrivateKey));
						Cipher cipher = Cipher.getInstance(pkInfo.getAlgName());
						PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
						SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pkInfo.getAlgName());
						Key pbeKey = pbeKeyFactory.generateSecret(keySpec);
						AlgorithmParameters algParams = pkInfo.getAlgParameters();
						cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
						KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
						PKCS8EncodedKeySpec keySpecPKCS8 = pkInfo.getKeySpec(cipher);
						return keyFactory.generatePrivate(keySpecPKCS8);
					} else {
						throw new IllegalArgumentException(CryptoConstants.PASSWORD_FOR_ENCRYPYED_KEY_IS_INVALID);
					}
				} else {
					throw new IllegalArgumentException(CryptoConstants.NO_PASSWORD_FOR_ENCRYPYED_KEY_IS_PROVIDED);
				}
			} else {
				throw new IllegalArgumentException(CryptoConstants.NO_PROPERTIES_JSON);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Converts a PKCS12 private key to a PrivateKey object.
	 *
	 * @return The PrivateKey object extracted from the PKCS12 file.
	 */
	protected static PrivateKey convertPKCS12ToPrivateKey() {
		try {
			String pfxData = GetResourcesFiles.getPrivateKeyAsString(PrivateKeyFormat.PKCS12);

			String privateKeyPassword = GetResourcesFiles.getPrivateKeyPassword(PrivateKeyFormat.PKCS12);

			if (privateKeyPassword != null) {

				JsonObject asJsonObject = JsonParser.parseString(privateKeyPassword).getAsJsonObject();

				if (asJsonObject.has(CryptoConstants.password)) {
					if (!asJsonObject.get(CryptoConstants.password).isJsonNull()
							&& asJsonObject.get(CryptoConstants.password) != null
							&& asJsonObject.get(CryptoConstants.password).getAsString() != "null") {

						String password = asJsonObject.get(CryptoConstants.password).getAsString();

						KeyStore keystore = KeyStore.getInstance(CryptoConstants.PKCS12);
						char[] passwordArray = password.toCharArray();
						keystore.load(new ByteArrayInputStream(Base64.getDecoder().decode(pfxData)), passwordArray);
						String alias = keystore.aliases().nextElement();
						return (PrivateKey) keystore.getKey(alias, passwordArray);
					} else {
						throw new IllegalArgumentException(CryptoConstants.PASSWORD_FOR_ENCRYPYED_KEY_IS_INVALID);
					}
				} else {
					throw new IllegalArgumentException(CryptoConstants.NO_PASSWORD_FOR_ENCRYPYED_KEY_IS_PROVIDED);
				}
			} else {
				throw new IllegalArgumentException(CryptoConstants.NO_PROPERTIES_JSON);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Converts an XML private key to a PrivateKey object.
	 *
	 * @return The PrivateKey object extracted from the XML.
	 */
	protected static PrivateKey convertXmlToPrivateKey() {
		try {
			String xmlKey = GetResourcesFiles.getPrivateKeyAsString(PrivateKeyFormat.XML);
			// Add BouncyCastle as a Security Provider
			Security.addProvider(new BouncyCastleProvider());

			// Parse the XML
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(new InputSource(new StringReader(xmlKey)));

			BigInteger modulus = new BigInteger(1,
					Base64.getDecoder().decode(getTextContentOfTag(document, "Modulus")));
			BigInteger publicExponent = new BigInteger(1,
					Base64.getDecoder().decode(getTextContentOfTag(document, "Exponent")));
			// Extract RSA parameters from XML
			BigInteger privateExponent = new BigInteger(1,
					Base64.getDecoder().decode(getTextContentOfTag(document, "D")));
			BigInteger primeP = new BigInteger(1, Base64.getDecoder().decode(getTextContentOfTag(document, "P")));
			BigInteger primeQ = new BigInteger(1, Base64.getDecoder().decode(getTextContentOfTag(document, "Q")));
			BigInteger primeExponentP = new BigInteger(1,
					Base64.getDecoder().decode(getTextContentOfTag(document, "DP")));
			BigInteger primeExponentQ = new BigInteger(1,
					Base64.getDecoder().decode(getTextContentOfTag(document, "DQ")));
			BigInteger crtCoefficient = new BigInteger(1,
					Base64.getDecoder().decode(getTextContentOfTag(document, "InverseQ")));

			// Create RSA private key
			RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP,
					primeQ, primeExponentP, primeExponentQ, crtCoefficient);
			KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
			return keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Gets the text content of a specified XML tag from a Document.
	 *
	 * @param document The XML Document.
	 * @param tagName  The name of the XML tag.
	 * @return The text content of the specified XML tag.
	 */
	private static String getTextContentOfTag(Document document, String tagName) {
		NodeList elements = document.getElementsByTagName(tagName);
		if (elements.getLength() == 0) {
			return null; // Or handle the missing tag appropriately
		}
		Element element = (Element) elements.item(0);
		return element.getTextContent().trim();
	}

	/**
	 * Converts a PKCS1 private key to a PrivateKey object.
	 *
	 * @return The PrivateKey object converted from PKCS1 to PKCS8 format.
	 */
	protected static PrivateKey convertPkcs1ToPrivateKey() {
		try {
			String pkcs1Key = GetResourcesFiles.getPrivateKeyAsString(PrivateKeyFormat.PKCS1);
			// Remove headers and decode
			pkcs1Key = pkcs1Key.replace("-----BEGIN RSA PRIVATE KEY-----", "");
			pkcs1Key = pkcs1Key.replace("-----END RSA PRIVATE KEY-----", "");
			pkcs1Key = pkcs1Key.replaceAll("\\s", "");

			System.out.println("Debug: Base64 String - " + pkcs1Key); // Debugging statement
			byte[] pkcs1Bytes = Base64.getDecoder().decode(pkcs1Key);

			// Convert PKCS#1 to PKCS#8
			RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(pkcs1Bytes);
			AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
			byte[] pkcs8Bytes = new PrivateKeyInfo(algId, rsaPrivateKey.toASN1Primitive()).getEncoded();

			// Generate PrivateKey
			KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
			return keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Converts a JWK private key to a PrivateKey object.
	 *
	 * @return The PrivateKey object extracted from the JWK.
	 */
	protected static PrivateKey convertJwkToPrivateKey() {
		try {
			String jwkKey = GetResourcesFiles.getPrivateKeyAsString(PrivateKeyFormat.JWK);
			JSONObject jwk = new JSONObject(jwkKey);
			BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getString("n")));
			BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getString("e")));
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, e);
			KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
			return keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Converts a PKCS8 private key to a PrivateKey object.
	 *
	 * @return The PrivateKey object converted from PKCS8 format.
	 */
	protected static PrivateKey convertPkcs8ToPrivateKey() {
		try {
			StringBuilder pkcs8Lines = new StringBuilder();
			BufferedReader reader = new BufferedReader(
					new StringReader(GetResourcesFiles.getPrivateKeyAsString(PrivateKeyFormat.PKCS8)));
			String line;
			while ((line = reader.readLine()) != null) {
				if (!line.startsWith("--")) {
					pkcs8Lines.append(line);
				}
			}

			// Base64 decode the result
			byte[] pkcs8Bytes = Base64.getDecoder().decode(pkcs8Lines.toString());

			// Generate the private key
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
			KeyFactory kf = KeyFactory.getInstance(CryptoConstants.RSA);
			return kf.generatePrivate(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
