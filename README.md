# Crypto Security Lib

Welcome to the `Crypto Security Lib` repository! This library provides encryption and decryption functionalities using private and public keys, supporting a variety of algorithms under AES and RSA. In this README, we'll cover the services offered by the `Crypto-security-lib`, how to use this library and also how to import it into your project.

## Services Provided
1. **Encryption Service:** Encrypt your data with `AES` and `RSA` algorithms with different mode and padding with your `PrivateKey` and `PublicKey`.
2. **Decryption Service:** Decrypt your data with `AES` and `RSA` algorithms with different mode and padding with your `PrivateKey` and `PublicKey`.

## Algorithms

### CryptographicAlgos
Supported cryptographic algorithms.

1. `AES` : Advanced Encryption Standard .
2. `RSA` : Rivest–Shamir–Adleman .

### AESModePadding
Supported modes and paddings for the AES algorithm.

1. `CBC_PKCS5Padding` : Cipher Block Chaining (CBC) mode with PKCS5 padding.
2. `GCM_NoPadding`    : Galois/Counter Mode (GCM) with no padding.
3. `ECB_PKCS5Padding` : Electronic Codebook (ECB) mode with PKCS5 padding.
4. `CBC_NoPadding`    : Cipher Block Chaining (CBC) mode with no padding.
5. `CTR_NoPadding`    : Counter (CTR) mode with no padding.
6. `CFB_NoPadding`    : Cipher Feedback (CFB) mode with no padding.
7. `ECB_NoPadding`    : Electronic Codebook (ECB) mode with no padding.
8. `OFB_NoPadding`    : Output Feedback (OFB) mode with no padding.
9. `CCM_NoPadding`    : Counter with CBC-MAC (CCM) mode with no padding.
10. `CFB8_NoPadding`  : Cipher Feedback 8 (CFB8) mode with no padding.

### RSAModePadding
Supported modes and paddings for the RSA algorithm.

1. `ECB_PKCS1Padding`        : RSA with PKCS1 padding in Electronic CodeBook (ECB) mode.
2. `ECB_NoPadding`           : RSA in Electronic CodeBook (ECB) mode with no padding.
3. `OAEP_SHA256_MGF1Padding` : RSA with Optimal Asymmetric Encryption Padding (OAEP) using SHA-256 and MGF1 padding in ECB mode.
4. `OAEP_SHA1_MGF1Padding`   : RSA with OAEP using SHA-1 and MGF1 padding in ECB mode.
5. `OAEP_SHA1_NoPadding`     : RSA with OAEP using SHA-1 and MGF1 padding in ECB mode with no additional padding.
6. `OAEP_SHA256_NoPadding`   : RSA with OAEP using SHA-256 and MGF1 padding in ECB mode with no additional padding.
7. `OAEP_SHA224_MGF1Padding` : RSA with OAEP using SHA-224 and MGF1 padding in ECB mode.
8. `OAEP_SHA512_MGF1Padding` : RSA with OAEP using SHA-512 and MGF1 padding in ECB mode.

## Key Formats

### PrivateKeyFormat
Supported formats for private keys.

1. `Encrypted_PKCS8` : Represents an encrypted private key in PKCS#8 format. PEM Header: "BEGIN ENCRYPTED PRIVATE KEY"
2. `PKCS12`          : Represents a private key typically in PKCS#12 (PFX) format. This is often used in scenarios where the key is bundled with a certificate.
3. `PKCS1`           : Represents a private key in PKCS#1 format. PEM Header: "BEGIN RSA PRIVATE KEY"
4. `PKCS8`           : Represents a private key in unencrypted PKCS#8 format. PEM Header: "BEGIN PRIVATE KEY"
5. `XML`             : Represents a private key in XML format. Typically formatted with an <RSAKeyValue> element.
6. `JWK`             : Represents a private key in JSON Web Key (JWK) format. Key Type: "RSA"

### PublicKeyFormat
Supported formats for public RSA keys.

1. `PKCS1`        : PEM Header -> "BEGIN RSA PUBLIC KEY"
2. `X509`         : certificate.cer file
3. `XML`          : Format represented in XML, typically with <RSAKeyValue> element
4. `PEM`          : PEM Header -> "BEGIN PUBLIC KEY"
5. `Encoded_X509` : PEM Header -> "BEGIN CERTIFICATE"

## Modals

### 1. EncryptedPayload
Represents a payload containing an encrypted key and encrypted data.
```example of EncryptedPayload.json
{
    "encryptedKey": "OiZ5DjvZx1xTyfHAyNF2IFLuH421KdKgDsPfhQ2cHX9ppQsGQwRwyE+DoNORW3WgY5BPAfrGtADB9nBLK7bAq11ldDTzgqYcNni71R4tB30joDG5FhYaaiXyqbBjDnq57OZx3ROJi+pnJQd6WJnEvTBy9xhZ/9NGonoiBK6u2XOUlN6bVM5ZFiouBbEFsGJdoIf9B0Su8Ud9lC9uz17sWgl0y852yZIZKdYQPb54IbjgXgRHiTvKXiFyumvogcY30PIa+sFEDK6gkjamE6QX9QjmOqt3n1L3PYK6B5tDhNrCZo2mps/DZ728TN/3yDpADpp4tjXJglWmOrm+6kfNXA\u003d\u003d",
    "encryptedData": "SUhLcnhDRWhuQUVkdVFzTk1c0LPlprOsPEwMLbWoYpA\u003d"
}
```

### 2. DecryptedPayload
Represents a payload containing a decrypted key and associated decrypted data.
```example of DecryptedPayload.json
{
    "decryptedKey": "IHKrxCEhnAEduQsN",
    "decryptedData": "Hello World!!"
}
```

## How to Use Crypto Security Lib

### 1. Maven Configuration
Add the following Maven repository to your project's `pom.xml`:

```pom.xml
<repositories>
    <repository>
        <id>crypto.lib</id>
        <url>https://maven.pkg.github.com/yashrockstar/Crypto-security-lib</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>
```

### 2. Dependency
Add the dependency for Crypto Security Lib:
```pom.xml
<dependency>
    <groupId>ai.crypto</groupId>
    <artifactId>security</artifactId>
    <version>VERSION</version>
</dependency>
```

## Pre-requisites
Before jumping to the `Initialization` part there is something which we have to keep in mind.

### Location and Naming Conventions of Private and Public key files
1. **Location** : All the files must be in the `src/main/resources` folder
2. **Naming Convention for Public key** : `PublicKey_<PublicKeyFormat>` except `PublicKeyFormat` as `X509` because in that case you have to provide `certificate.cer` file
3. **Naming Convention for Private key** : `PrivateKey_<PrivateKeyFormat>`
4. **Naming Convention for Public Certificate** : `certificate.cer`
5. **Naming Convention for Properties file** : `properties_<PrivateKeyFormat>.json`

`NOTE` What is `properties_<PrivateKeyFormat>.json` (In Case you are using encrypted Private Key)
This json file will contain the password for that `encrypted PrivateKey`
```properties_<PrivateKeyFormat>.json
{
	"password" : "YOUR_PASSWORD"
}
```
#### Example :

If the `public key format` is `PEM` and `private key format` is `PKCS8`
1. **Naming Convention for Public key** : `PublicKey_PEM`
2. **Naming Convention for Private key** : `PrivateKey_PKCS8`

If the `public key format` is `PEM` and `private key format` is `Encrypted_PKCS8` (Encrypted one)
1. **Naming Convention for Public key** : `PublicKey_PEM`
2. **Naming Convention for Private key** : `PrivateKey_Encrypted_PKCS8`
3. **Naming Convention for Properties file** : `properties_Encrypted_PKCS8.json`


`NOTE` Things to keep in mind when we are using `certificate.cer` as public key
In this case we'll be choosing `PublicKeyFormat` as `X509`

## Initialization
To start using `Crypto Security Lib`, initialize a cryptographic algorithm using the `CryptoSecurityService` class. This class provides a convenient method to initialize cryptographic algorithms with specified parameters.

```java
CryptographicAlgorithm init = CryptoSecurityService.init(CryptographicAlgos.AES,
    AESModePadding.CBC_PKCS5Padding, PrivateKeyFormat.PKCS8, PublicKeyFormat.X509);
```

### Encryption and Decryption
Once initialized, you can use the CryptographicAlgorithm instance to encrypt and decrypt data.

#### 1. Encryption Process
```java
EncryptedPayload encryptedPayload = init.encrypt(data);
String encryptedData = new Gson().toJson(encryptedPayload);
```
#### 2. Decryption Process
```java
DecryptedPayload decryptedPayload = init.decrypt(encryptedData);
```

