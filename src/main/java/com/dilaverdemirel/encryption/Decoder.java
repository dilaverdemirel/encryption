package com.dilaverdemirel.encryption;

import com.dilaverdemirel.encryption.exception.EncryptionDecryptionException;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

/**
 * @author dilaverdemirel@gmail.com
 */
public class Decoder {
    private Config config;
    private Key secretKey;

    public Decoder(Config config, Key secretKey) {
        this.config = config;
        this.secretKey = secretKey;
    }

    public byte[] decode(String encryptedMessage) throws EncryptionDecryptionException {
        return decode(encryptedMessage,null);
    }

    /**
     *
     * @param encryptedMessageStr
     * @param aditionalTagDataStr Any random data can be used as tag. Some common examples could be domain name...
     * @return
     * @throws EncryptionDecryptionException
     */
    public byte[] decode(String encryptedMessageStr, String aditionalTagDataStr) throws EncryptionDecryptionException {

        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageStr);
        byte[] aditionalTagData = null;

        if(aditionalTagDataStr != null) {
            aditionalTagData = aditionalTagDataStr.getBytes();
        }

        Cipher c = null;

        try {
            c = Cipher.getInstance(config.getAlgorithmTransformationString()); // Transformation specifies algortihm, mode of operation and padding
        } catch (NoSuchAlgorithmException noSuchAlgoExc) {
            throw new EncryptionDecryptionException("Exception while decrypting. Algorithm being requested is not available in environment " + noSuchAlgoExc);
        } catch (NoSuchPaddingException noSuchAlgoExc) {
            throw new EncryptionDecryptionException("Exception while decrypting. Padding scheme being requested is not available in environment " + noSuchAlgoExc);
        }

        try {
            if (config.getAlgorithmParameterSpec() != null){
                c.init(Cipher.DECRYPT_MODE, secretKey, (AlgorithmParameterSpec) config.getAlgorithmParameterSpec(), new SecureRandom());
            } else {
                c.init(Cipher.DECRYPT_MODE, secretKey,new SecureRandom());
            }
        } catch (InvalidKeyException invalidKeyExc) {
            throw new EncryptionDecryptionException("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc);
        } catch (InvalidAlgorithmParameterException invalidParamSpecExc) {
            throw new EncryptionDecryptionException("Exception while encrypting. Algorithm Param being used is not valid. " + invalidParamSpecExc);
        }

        try {
            if(aditionalTagData != null) {
                c.updateAAD(aditionalTagData); // Add AAD details before decrypting
            }
        } catch (IllegalArgumentException illegalArgumentExc) {
            throw new EncryptionDecryptionException("Exception thrown while encrypting. Byte array might be null " + illegalArgumentExc);
        } catch (IllegalStateException illegalStateExc) {
            throw new EncryptionDecryptionException("Exception thrown while encrypting. CIpher is in an illegal state " + illegalStateExc);
        }

        byte[] plainTextInByteArr = null;
        try {
            plainTextInByteArr = c.doFinal(encryptedMessage);
        } catch (IllegalBlockSizeException illegalBlockSizeExc) {
            throw new EncryptionDecryptionException("Exception while decryption, due to block size " + illegalBlockSizeExc);
        } catch (BadPaddingException badPaddingExc) {
            throw new EncryptionDecryptionException("Exception while decryption, due to padding scheme " + badPaddingExc);
        }

        return plainTextInByteArr;
    }
}
