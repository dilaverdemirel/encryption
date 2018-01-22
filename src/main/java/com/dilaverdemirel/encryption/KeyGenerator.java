package com.dilaverdemirel.encryption;

import com.dilaverdemirel.encryption.exception.EncryptionDecryptionException;

import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author dilaverdemirel@gmail.com
 * @param <T> Symmetric : SecretKey, Asymmetric : KeyPair
 */

public class KeyGenerator<T> {
    private KeyGeneratorConfig config;

    public KeyGenerator(KeyGeneratorConfig config) {
        this.config = config;
    }

    public T generate() throws EncryptionDecryptionException {
        try {
            if (KeyGeneratorConfig.EncDecType.symmetric.equals(config.getEncDecType())) {
                return createSymmetricKey();
            } else if (KeyGeneratorConfig.EncDecType.asymmetric.equals(config.getEncDecType())) {
                return createAsymmetricKeyPair();
            }
        } catch (NoSuchAlgorithmException noSuchAlgoExc) {
            throw new EncryptionDecryptionException("Key being request is for " + config.getAlgorithm() + " algorithm, but this cryptographic algorithm is not available in the environment " + noSuchAlgoExc);
        }

        return null;
    }

    private T createAsymmetricKeyPair() throws NoSuchAlgorithmException {
        if (KeyGeneratorConfig.EncDecType.asymmetric.equals(config.getEncDecType())) {
            // Generate Key Pairs
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(config.getAlgorithm());
            keygen.initialize(config.getKeySize());
            KeyPair keyPair = keygen.generateKeyPair();
            return (T) keyPair;
        } else {
            throw new EncryptionDecryptionException("Incorrect key creation request. Please call createSymmetricKey method.");
        }
    }

    private T createSymmetricKey() throws NoSuchAlgorithmException {
        if (KeyGeneratorConfig.EncDecType.symmetric.equals(config.getEncDecType())) {
            // Generating Key
            javax.crypto.KeyGenerator keygen = javax.crypto.KeyGenerator.getInstance(config.getAlgorithm()); // Specifying algorithm key will be used for
            keygen.init(config.getKeySize()); // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly
            return (T) keygen.generateKey();
        } else {
            throw new EncryptionDecryptionException("Incorrect key creation request. Please call createAsymmetricKeyPair method.");
        }
    }

    public String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public Key stringToSecretKey(String keyString) {
        byte[] decodedKey = getBytesFromKeyString(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, config.getAlgorithm());
    }

    public Key stringToPublicKey(String keyString) {
        byte[] decodedKey = getBytesFromKeyString(keyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        try {
            return getKeyFactory().generatePublic(keySpec);
        } catch (Exception e) {
            throw new EncryptionDecryptionException(e.getMessage());
        }
    }

    public Key stringToPrivateKey(String keyString) {
        byte[] decodedKey = getBytesFromKeyString(keyString);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodedKey);
        try {
            return getKeyFactory().generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            throw new EncryptionDecryptionException(e.getMessage());
        }
    }

    private byte[] getBytesFromKeyString(String keyString) {
        return Base64.getDecoder().decode(keyString);
    }

    private KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(config.getAlgorithm());
    }
}
