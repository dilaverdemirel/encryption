package com.dilaverdemirel.encryption;


import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import com.dilaverdemirel.encryption.exception.EncryptionDecryptionException;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * @author dilaverdemirel@gmail.com
 *
 */
public class SymmetricEncryptionDecryptionTest {
    private static final int vectorSize = 96;
    private static final String algorithm = "AES";
    private static final int keySize = 128;

    private static final String aditionalTagData = "dilaverdemirel.com";
    private static final String clearText = "Encrypt it!";
    private static final String iv = "2Bo84Z92OUk2NxgJVqm0EE2J27lSfWJNmpzV6qqKgAr5fS6Fd9jIO8lWwCdPNJMH4beBE4v91P6ybOEEDidQE3RLNlc8+FFCu77wxlz/Nsk6L8njvaj0aXE0yvzH16uV";
    private static final String encodedText = "ue2FA7iUun8rXykoONOUDN9xagco7Y30+opD";

    private static final String secretKey = "rCuFJMvI3WVJaMzYPmTc2A==";
    private static final Config<GCMParameterSpec> config = new Config<GCMParameterSpec>();
    private static KeyGenerator<SecretKey> keyGenerator;

    @BeforeClass
    public static void beforeTest(){
        SymmetricEncryptionDecryptionTest.config.setAlgorithm(algorithm);
        SymmetricEncryptionDecryptionTest.config.setKeySize(keySize);

        KeyGeneratorConfig keyGeneratorConfig = new KeyGeneratorConfig();
        keyGeneratorConfig.setAlgorithm(SymmetricEncryptionDecryptionTest.config.getAlgorithm());
        keyGeneratorConfig.setKeySize(SymmetricEncryptionDecryptionTest.config.getKeySize());
        keyGeneratorConfig.setEncDecType(KeyGeneratorConfig.EncDecType.symmetric);
        SymmetricEncryptionDecryptionTest.keyGenerator = new KeyGenerator<SecretKey>(keyGeneratorConfig);

        SymmetricEncryptionDecryptionTest.config.setAlgorithm(algorithm);
        SymmetricEncryptionDecryptionTest.config.setModeOfOperation("GCM");
        SymmetricEncryptionDecryptionTest.config.setPadding("PKCS5Padding");
        SymmetricEncryptionDecryptionTest.config.setInitializationVectorSize(vectorSize);
        SymmetricEncryptionDecryptionTest.config.setAuthenticationTagBitLength(128);
        SymmetricEncryptionDecryptionTest.config.setMessageCharset("UTF-8");
    }

    @Test
    public void testKeyGeneratorGenerateKeyAsObject() throws EncryptionDecryptionException {
        SecretKey key = keyGenerator.generate();
        Assert.assertNotNull(key);
    }

    @Test
    public void testKeyGeneratorGenerateKeyAsString() throws EncryptionDecryptionException {
        SecretKey key = keyGenerator.generate();
        String keyAsString = keyGenerator.keyToString(key);
        System.out.println("keyAsString = " + keyAsString);
        Assert.assertNotNull(keyAsString);
    }

    @Test
    public void testKeyGeneratorSecretKeyToString() throws EncryptionDecryptionException {
        byte[] encoded = Base64.getDecoder().decode(secretKey);
        String keyAsString = keyGenerator.keyToString(new SecretKeySpec(encoded, config.getAlgorithm()));
        Assert.assertNotNull(keyAsString);
    }

    @Test
    public void testKeyGeneratorStringToSecretKey() throws EncryptionDecryptionException {
        SecretKey secretKey = (SecretKey) keyGenerator.stringToSecretKey(SymmetricEncryptionDecryptionTest.secretKey);
        Assert.assertNotNull(secretKey);
    }

    @Test
    public void testEncodeWithAdditionalData() throws EncryptionDecryptionException, UnsupportedEncodingException {
        SecretKey secretKey = (SecretKey) keyGenerator.stringToSecretKey(SymmetricEncryptionDecryptionTest.secretKey);
        Encoder encoder = new Encoder(config,secretKey);

        byte[] initializationVector = Base64.getDecoder().decode(iv);

        String encodedIV = Base64.getEncoder().encodeToString(initializationVector);
        System.out.println("initVectorStr:"+ encodedIV);

        config.setAlgorithmParameterSpec(new GCMParameterSpec(config.getAuthenticationTagBitLength(), initializationVector));

        byte[] encodedData = encoder.encode(clearText,aditionalTagData);
        System.out.println("encodedData = " + Base64.getEncoder().encodeToString(encodedData));
        Assert.assertNotNull(encodedData);
    }

    @Test
    public void tetGenerateInitializationVector(){
        byte[] initializationVector = EncryptionUtil.getInitializationVector(config.getInitializationVectorSize());
        String encoded = Base64.getEncoder().encodeToString(initializationVector);
        System.out.println("initVectorStr:"+ encoded);
    }

    @Test
    public void testDecodeWithAdditionalData() throws EncryptionDecryptionException, UnsupportedEncodingException {
        SecretKey secretKey = (SecretKey) keyGenerator.stringToSecretKey(SymmetricEncryptionDecryptionTest.secretKey);

        byte[] initializationVector = Base64.getDecoder().decode(iv);
        config.setAlgorithmParameterSpec(new GCMParameterSpec(config.getAuthenticationTagBitLength(), initializationVector));

        Decoder decoder = new Decoder(config,secretKey);

        byte[] decodedData = decoder.decode(encodedText,aditionalTagData);
        System.out.println("decodedData = " + new String(decodedData));
        Assert.assertNotNull(decodedData);
        Assert.assertEquals(clearText,new String(decodedData));
    }
}
