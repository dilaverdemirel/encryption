package com.dilaverdemirel.encryption;


import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import com.dilaverdemirel.encryption.exception.EncryptionDecryptionException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * @author dilaverdemirel@gmail.com
 */
public class AsymmetricEncryptionDecryptionTest {
    private static final String algorithm = "RSA";
    private static final int keySize = 4096;

    private static final String clearText = "Encrypt it!";
    private static final String encodedText = "D6/YRIpmGPgkZDKfRB7LXDSqytka2ZV2ZW+qHl/tX0V9Uts9SwDJ+or/7GDQwevt2zsIiQ4BnflExk9uS4UZKHEdAW71Gm7fL1O8eFCPHG0bMLt0LyhV3PhVU6hx6ro7f5ZX365ElgUYCYicGkqwhI4q5T2k7bq5QbzVs1NMO94jULJErZ4QTEYpwHaIeteBnHXDOdiVJX9xNwCGKBlEx/PUCaAjfwK00L7ecDbtr+bmh7ElJh8p0+VX9ABTtqT3yqd+y8y6Nzl6oMRSDQaL7BGAZkiVYZ5j5DuWtnzdVoIN1c9lAmM/t0WyRfGEi9zuuku3L+gencFQi93gNnQq0gDo8oVlksUEFpFruI8+XEUC30IhRStRh261hYDMMKpFJ3ugk2OxGS9xtxpsI2vyKYO7f9FVSjztOApIGabItJ2jJn6k/9x2WL52wqmiPqVhRjLzNFEBHg28zcv1S4GzZJwZbDBSuypLJIgwPGacGyERUKdqMDHE2aOGFDDZQ+0MODeY1zCEVZ/PXAoxr1ngBpL7Sh1OJ9NfAnpQGwWje3B2PlBJKEwCF3GbYVmRlfgERXu416inL9bOTnIRD7F3S2OzK4+aiRhxZr6VtU2Oa0ND4601bzgxRAGlIiNdLOdZaWVfMTq0HIkdMweN+NeLBR8S8HHnsHjJmJzoi/n+IDE=";

    String privateKey = "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";
    String publicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk4tJviRcqMoKhd/gCzW8jnWr5R1IXCYgZ1vz0FUpevMI+3AwonFIuHhVzyfCBjUx6nBIThiJJrcx6Jve+/DI6WLNCqpDajb1jp7MTHc5nle7dZEylJ9HxTOUvdKS5FFbasTcWHYBp3nGCmIr7XIgo09Ki3Xp1a+WFDUIHfvVy+BW68/PsfnFW/oP16miAqeZL9pq39IybNlGty2KQ2UqYodMaDwg1n8nqD/ifXOptI2OxaTXgt+sqAKKB1t+jF1ayxgZGCzLVRFRgMQ4cx34cwnDXWdXlDFMY8T5iYnM4vAQ/iZwOHzWylG3Xl23VKpwai/HEZsir9OVlE6Ooj8YYACGWypG4e8zFDGz1IO2vILEUqP+HQGXPpPEAZ0qPZejhB5C85KjpJ9inTixBdoGXR+uURzhpxBFr1dz7Jl5RqAcXvmx18FoVvTyeUCSYoSNLuhVnE/1OgywIn6qxQ7hKsm3O0kQRjGhmzCmx4rD4Url9MIE0jDpQb92uuZ+Ms/ukQRzFr4kiNL1wq6COOB3zuj9xW2Q7L4P1MtBUihaVKiHfwQhJs9bDtzNsnWmVRFcWhPhhe2zgSJec7jTA+ekTO4UE721cM7yU7lmeV6b/sPgJ+3UENKO/7jkTnbvlxghY8VwL4oNIsSz5QofwfLDeoRGmR1xCSM1GnjT5nuDeIECAwEAAQ==";

    private static final Config config = new Config();
    private static KeyGenerator<KeyPair> keyGenerator;

    @BeforeClass
    public static void beforeTest() {
        AsymmetricEncryptionDecryptionTest.config.setAlgorithm(algorithm);
        AsymmetricEncryptionDecryptionTest.config.setKeySize(keySize);

        KeyGeneratorConfig keyGeneratorConfig = new KeyGeneratorConfig();
        keyGeneratorConfig.setAlgorithm(algorithm);
        keyGeneratorConfig.setKeySize(keySize);
        keyGeneratorConfig.setEncDecType(KeyGeneratorConfig.EncDecType.asymmetric);
        AsymmetricEncryptionDecryptionTest.keyGenerator = new KeyGenerator<KeyPair>(keyGeneratorConfig);

        AsymmetricEncryptionDecryptionTest.config.setAlgorithm(algorithm);
        AsymmetricEncryptionDecryptionTest.config.setModeOfOperation("ECB");
        AsymmetricEncryptionDecryptionTest.config.setPadding("OAEPWITHSHA-512ANDMGF1PADDING");
        AsymmetricEncryptionDecryptionTest.config.setMessageCharset("UTF-8");
    }

    @Test
    public void testKeyGeneratorGenerateKeyAsObject() throws EncryptionDecryptionException {
        KeyPair keyPair = keyGenerator.generate();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
    }

    @Test
    public void testKeyGeneratorGenerateKeyAsString() throws EncryptionDecryptionException {
        KeyPair keyPair = keyGenerator.generate();
        String privateKeyAsString = keyGenerator.keyToString(keyPair.getPrivate());
        System.out.println("privateKeyAsString = " + privateKeyAsString);
        Assert.assertNotNull(privateKeyAsString);

        String publicKeyAsString = keyGenerator.keyToString(keyPair.getPublic());
        System.out.println("publicKeyAsString = " + publicKeyAsString);
        Assert.assertNotNull(publicKeyAsString);
    }

    @Test
    public void testKeyGeneratorKeyToString() throws EncryptionDecryptionException {
        byte[] encodedPrivateKey = Base64.getDecoder().decode(privateKey);
        String privateKeyAsString = keyGenerator.keyToString(new SecretKeySpec(encodedPrivateKey, config.getAlgorithm()));
        Assert.assertNotNull(privateKeyAsString);

        byte[] encodedPublicKey = Base64.getDecoder().decode(publicKey);
        String publicKeyAsString = keyGenerator.keyToString(new SecretKeySpec(encodedPublicKey, config.getAlgorithm()));
        Assert.assertNotNull(publicKeyAsString);
    }

    @Test
    public void testKeyGeneratorStringToKey() throws EncryptionDecryptionException {
        SecretKey secretPrivateKey = (SecretKey) keyGenerator.stringToSecretKey(privateKey);
        Assert.assertNotNull(secretPrivateKey);

        SecretKey secretPublicKey = (SecretKey) keyGenerator.stringToSecretKey(publicKey);
        Assert.assertNotNull(secretPublicKey);
    }

    @Test
    public void testEncode() throws EncryptionDecryptionException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        Key key = keyGenerator.stringToPublicKey(publicKey);
        Encoder encoder = new Encoder(config, key);
        byte[] encodedData = encoder.encode(clearText);
        System.out.println("encodedData = " + Base64.getEncoder().encodeToString(encodedData));
        Assert.assertNotNull(encodedData);
    }

    @Test
    public void testDecode() throws EncryptionDecryptionException, UnsupportedEncodingException {
        Key privateKey = keyGenerator.stringToPrivateKey(this.privateKey);
        Decoder decoder = new Decoder(config, privateKey);
        byte[] decodedData = decoder.decode(encodedText);
        String decodedDataStr = new String(decodedData);
        System.out.println("decodedData = " + decodedDataStr);
        Assert.assertNotNull(decodedData);
        Assert.assertEquals(clearText,decodedDataStr);
    }


}
