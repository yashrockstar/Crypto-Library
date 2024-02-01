package ai.crypto.security.client.algo.utils.rsa.impl;

import java.security.PrivateKey;
import java.security.PublicKey;

import ai.crypto.security.client.algo.utils.CryptographicAlgorithm;
import ai.crypto.security.client.certificate.utils.CertUtils;
import ai.crypto.security.client.decryption.helper.DecryptionHelper;
import ai.crypto.security.client.encryption.helper.EncryptionHelper;
import ai.crypto.security.client.enums.CryptographicAlgos;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.enums.RSAModePadding;
import ai.crypto.security.client.modal.DecryptedPayload;
import ai.crypto.security.client.modal.EncryptedPayload;

/**
 * Implementation of the CryptographicAlgorithm interface for RSA encryption
 * with ECB mode and no padding.
 */
public class RSA_ECB_NoPadding_CryptographicAlgorithm implements CryptographicAlgorithm {

	PrivateKeyFormat privateKeyFormat;
	PublicKeyFormat publicKeyFormat;

	/**
	 * Constructor for RSA_ECB_NoPadding_CryptographicAlgorithm.
	 *
	 * @param <privateKeyFormat> The format of the private key.
	 * @param <publicKeyFormat>  The format of the public key.
	 */
	public RSA_ECB_NoPadding_CryptographicAlgorithm(PrivateKeyFormat privateKeyFormat,
			PublicKeyFormat publicKeyFormat) {
		this.privateKeyFormat = privateKeyFormat;
		this.publicKeyFormat = publicKeyFormat;
	}

	/**
	 * Encrypts the provided data using RSA with ECB mode and no padding.
	 *
	 * @param data The data to be encrypted.
	 * @return <EncryptedPayload> with encrypted key.
	 * @throws Exception If an error occurs during the encryption process.
	 */
	@Override
	public EncryptedPayload encrypt(String key) throws Exception {
		// Get the public key from the certificate utility
		PublicKey saleskenPublicKey = CertUtils.getInstance().getPublicKey(publicKeyFormat);

		// Convert the X.509 encoded public key to the appropriate RSA public key
		PublicKey x509Key = EncryptionHelper.getPublic(saleskenPublicKey.getEncoded(), CryptographicAlgos.getRSA());

		// Encrypt the data using RSA with ECB mode and no padding
		byte[] encrypt = EncryptionHelper.encrypt(key.getBytes(), x509Key,
				RSAModePadding.ECB_NoPadding.getAlgorithm());

		// Encode the encrypted key to base64
		return new EncryptedPayload(EncryptionHelper.encode(encrypt));
	}

	/**
	 * Decrypts the provided base64-encoded encrypted data using RSA with ECB mode
	 * and no padding.
	 *
	 * @param data The base64-encoded encrypted data.
	 * @return The <DecryptedPayload>.
	 * @throws Exception If an error occurs during the decryption process.
	 */
	@Override
	public DecryptedPayload decrypt(String data) throws Exception {
		// Get the private key from the certificate utility
		PrivateKey privateKey = CertUtils.getInstance().getPrivateKey(privateKeyFormat);

		// Decode the base64-encoded encrypted data
		byte[] decode = DecryptionHelper.decode(data);

		// Convert the PKCS#8 encoded private key to the appropriate RSA private key
		PrivateKey pkcs8PrivateKey = DecryptionHelper.getPrivate(privateKey.getEncoded(), CryptographicAlgos.getRSA());

		// Decrypt the data using RSA with ECB mode and no padding
		byte[] decryptedKey = DecryptionHelper.decrypt(decode, pkcs8PrivateKey,
				RSAModePadding.ECB_NoPadding.getAlgorithm());
		return new DecryptedPayload(new String(decryptedKey).trim());
	}
}
