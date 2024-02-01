package ai.crypto.security.client.certificate.utils;

import java.security.PrivateKey;
import java.security.PublicKey;

import ai.crypto.security.client.constants.CryptoErrorMessages;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;

/**
 * Utility class for handling certificates and keys in the crypto client
 * application.
 */
public class CertUtils {

	private static CertUtils certUtils;

	private CertUtils() {
	}

	/**
	 * Gets an instance of CertUtils using the singleton pattern.
	 *
	 * @return An instance of CertUtils.
	 */
	public static CertUtils getInstance() {
		if (certUtils == null) {
			synchronized (CertUtils.class) {
				if (certUtils == null) {
					certUtils = new CertUtils();
				}
			}
		}
		return certUtils;
	}

	/**
	 * Retrieves the private key from the <PrivateKeyFormat>.
	 *
	 * @return The private key.
	 */
	public PrivateKey getPrivateKey(PrivateKeyFormat privateKeyFormat) {

		if (privateKeyFormat == null) {
			privateKeyFormat = PrivateKeyUtils.detectPrivateKeyFormat();
		}
		
		switch (privateKeyFormat) {
		case Encrypted_PKCS8:
			return PrivateKeyUtils.convertEncrypted_PKCS8ToPrivateKey();
		case PKCS12:
			return PrivateKeyUtils.convertPKCS12ToPrivateKey();
		case XML:
			return PrivateKeyUtils.convertXmlToPrivateKey();
		case PKCS8:
			return PrivateKeyUtils.convertPkcs8ToPrivateKey();
		case PKCS1:
			return PrivateKeyUtils.convertPkcs1ToPrivateKey();
		case JWK:
			return PrivateKeyUtils.convertJwkToPrivateKey();
		default:
			throw new IllegalArgumentException(CryptoErrorMessages.UNSUPPORTED_PRIVATE_KEY_FORMAT);
		}
	}

	/**
	 * Retrieves the public key from the <PublicKeyFormat>.
	 *
	 * @return The public key.
	 */
	public PublicKey getPublicKey(PublicKeyFormat publicKeyFormat) {
		
		if (publicKeyFormat == null) {
			publicKeyFormat = PublicKeyUtils.detectPublicKeyFormat();
		}
		
		switch (publicKeyFormat) {
		case X509:
			return PublicKeyUtils.convertX509ToPublicKey();
		case PEM:
			return PublicKeyUtils.convertPEMToPublicKey();
		case Encoded_X509:
			return PublicKeyUtils.convertEncoded_X509ToPublicKey();
		case XML:
			return PublicKeyUtils.convertXmlToPublicKey();
		case PKCS1:
			return PublicKeyUtils.convertPkcs1ToPublicKey();
		default:
			throw new IllegalArgumentException(CryptoErrorMessages.UNSUPPORTED_PUBLIC_KEY_FORMAT);
		}
	}

}
