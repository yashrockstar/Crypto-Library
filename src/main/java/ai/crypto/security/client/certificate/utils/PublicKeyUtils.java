package ai.crypto.security.client.certificate.utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import ai.crypto.security.client.constants.CryptoConstants;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.utils.GetResourcesFiles;

/**
 * The `PublicKeyUtils` class provides utility methods for detecting and
 * converting public keys in various formats such as PKCS1, PEM, XML, Encoded
 * X.509, and PKCS1.
 */
public class PublicKeyUtils {

	/**
	 * Detects the format of the public key based on its content.
	 *
	 * @return The detected public key format.
	 * @throws IllegalArgumentException If the public key format is unknown or
	 *                                  unsupported.
	 */
	public static PublicKeyFormat detectPublicKeyFormat() {
		try (InputStream is = CertUtils.class.getClassLoader().getResourceAsStream(CryptoConstants.PublicKey);
				BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.contains(CryptoConstants.PKCS1_public_header)) {
					return PublicKeyFormat.PKCS1;
				} else if (line.contains(CryptoConstants.PEM_header)) {
					return PublicKeyFormat.PEM;
				} else if (line.contains(CryptoConstants.XML_header)) {
					return PublicKeyFormat.XML;
				} else if (line.startsWith(CryptoConstants.Encoded_X509_header)) {
					return PublicKeyFormat.Encoded_X509;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new IllegalArgumentException("Unknown or unsupported public key format");
	}

	/**
	 * Converts an X.509 public key to a PublicKey object.
	 *
	 * @return The PublicKey object extracted from the X.509 certificate.
	 */
	protected static PublicKey convertX509ToPublicKey() {
		CertificateFactory certificateFactory = null;
		try {
			certificateFactory = CertificateFactory.getInstance(CryptoConstants.X_509);
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		X509Certificate certificate = null;
		try {
			certificate = (X509Certificate) certificateFactory
					.generateCertificate(GetResourcesFiles.getPublicKeyAsInputStream());
		} catch (CertificateException e) {
			throw new IllegalArgumentException(CryptoConstants.NO_CERTIFICATE);
		}
		PublicKey publicKey = certificate.getPublicKey();
		return publicKey;
	}

	/**
	 * Converts an XML public key to a PublicKey object.
	 *
	 * @return The PublicKey object extracted from the XML.
	 */
	protected static PublicKey convertXmlToPublicKey() {
		try {
			String xmlKey = GetResourcesFiles.getPublicKeyAsString(PublicKeyFormat.XML);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(new ByteArrayInputStream(xmlKey.getBytes()));
			NodeList modulusNode = document.getElementsByTagName("Modulus");
			NodeList exponentNode = document.getElementsByTagName("Exponent");

			byte[] modulusBytes = Base64.getDecoder().decode(modulusNode.item(0).getTextContent());
			byte[] exponentBytes = Base64.getDecoder().decode(exponentNode.item(0).getTextContent());

			BigInteger modulus = new BigInteger(1, modulusBytes);
			BigInteger exponent = new BigInteger(1, exponentBytes);

			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
			return keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Converts a PKCS1 public key to a PublicKey object.
	 *
	 * @return The PublicKey object converted from PKCS1 to PKCS8 format.
	 */
	protected static PublicKey convertPkcs1ToPublicKey() {
		try {
			String pkcs1Key = GetResourcesFiles.getPublicKeyAsString(PublicKeyFormat.PKCS1);
			pkcs1Key.replace("-----BEGIN RSA PUBLIC KEY-----", "");
			pkcs1Key.replace("-----END RSA PUBLIC KEY-----", "");
			pkcs1Key.replaceAll("\\s", "");
			byte[] pkcs1Bytes = Base64.getDecoder().decode(pkcs1Key);

			RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(pkcs1Bytes);
			BigInteger modulus = rsaPublicKey.getModulus();
			BigInteger publicExponent = rsaPublicKey.getPublicExponent();

			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
			KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
			return keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Converts an Encoded X.509 public key to a PublicKey object.
	 *
	 * @return The PublicKey object extracted from the encoded X.509 certificate.
	 */
	protected static PublicKey convertEncoded_X509ToPublicKey() {
		try {
			String x509CertificatePEM = GetResourcesFiles.getPublicKeyAsString(PublicKeyFormat.Encoded_X509);

			// Remove "BEGIN" and "END" lines, as well as any whitespace
			x509CertificatePEM = x509CertificatePEM.replace("-----BEGIN CERTIFICATE-----", "");
			x509CertificatePEM = x509CertificatePEM.replace("-----END CERTIFICATE-----", "");
			x509CertificatePEM = x509CertificatePEM.replaceAll("\\s+", "");

			// Base64 decode the result
			byte[] x509CertificateBytes = Base64.getDecoder().decode(x509CertificatePEM);

			// Generate public key from X.509 certificate bytes
			CertificateFactory certificateFactory = CertificateFactory.getInstance(CryptoConstants.X_509);
			X509Certificate x509Certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(x509CertificateBytes));

			return x509Certificate.getPublicKey();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Converts a PEM public key to a PublicKey object.
	 *
	 * @return The PublicKey object extracted from the PEM key.
	 */
	protected static PublicKey convertPEMToPublicKey() {
		try {
			String pemKey = GetResourcesFiles.getPublicKeyAsString(PublicKeyFormat.PEM);
			pemKey = pemKey.replace("-----BEGIN PUBLIC KEY-----", "");
			pemKey = pemKey.replace("-----END PUBLIC KEY-----", "");
			pemKey = pemKey.replaceAll("\\s+", "");

			byte[] pemEncodedBytes = Base64.getDecoder().decode(pemKey);

			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemEncodedBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.RSA);
			return keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
