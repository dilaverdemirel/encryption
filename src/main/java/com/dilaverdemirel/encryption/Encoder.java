package com.dilaverdemirel.encryption;

import com.dilaverdemirel.encryption.exception.EncryptionDecryptionException;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author dilaverdemirel@gmail.com
 */
public class Encoder {
    private Config config;
    private Key secretKey;

    public Encoder(Config config, Key secretKey) {
        this.config = config;
        this.secretKey = secretKey;
    }

    public byte[] encode(String message) throws EncryptionDecryptionException {
        return encode(message,null);
    }

    /**
     *
     * @param message
     * @param aditionalTagDataStr Any random data can be used as tag. Some common examples could be domain name...
     * @return
     * @throws EncryptionDecryptionException
     */
    public byte[] encode(String message, String aditionalTagDataStr) throws EncryptionDecryptionException {
        byte[] aditionalTagData = null;

        if(aditionalTagDataStr != null) {
            aditionalTagData = aditionalTagDataStr.getBytes();
        }

        Cipher c = null;

        try {
            c = Cipher.getInstance(config.getAlgorithmTransformationString()); // Transformation specifies algortihm, mode of operation and padding
        } catch (NoSuchAlgorithmException noSuchAlgoExc) {
            throw new EncryptionDecryptionException("Exception while encrypting. Algorithm being requested is not available in this environment " + noSuchAlgoExc);
        } catch (NoSuchPaddingException noSuchPaddingExc) {
            throw new EncryptionDecryptionException("Exception while encrypting. Padding Scheme being requested is not available this environment " + noSuchPaddingExc);
        }

        try {
            if (config.getAlgorithmParameterSpec() != null){
                c.init(Cipher.ENCRYPT_MODE, secretKey, (AlgorithmParameterSpec) config.getAlgorithmParameterSpec(), new SecureRandom());
            } else {
                c.init(Cipher.ENCRYPT_MODE, secretKey,new SecureRandom());
            }
        } catch (InvalidKeyException invalidKeyExc) {
            throw new EncryptionDecryptionException("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc);
        } catch (InvalidAlgorithmParameterException invalidAlgoParamExc) {
            throw new EncryptionDecryptionException("Exception while encrypting. Algorithm parameters being specified are not valid " + invalidAlgoParamExc);
        }

        try {
            if(aditionalTagData != null) {
                c.updateAAD(aditionalTagData); // add AAD tag data before encrypting
            }
        } catch (IllegalArgumentException illegalArgumentExc) {
            throw new EncryptionDecryptionException("Exception thrown while encrypting. Byte array might be null " + illegalArgumentExc);
        } catch (IllegalStateException illegalStateExc) {
            throw new EncryptionDecryptionException("Exception thrown while encrypting. CIpher is in an illegal state " + illegalStateExc);
        } catch (UnsupportedOperationException unsupportedExc) {
            throw new EncryptionDecryptionException("Exception thrown while encrypting. Provider might not be supporting this method " + unsupportedExc);
        }

        byte[] cipherTextInByteArr = null;
        try {
            cipherTextInByteArr = c.doFinal(message.getBytes(config.getMessageCharset()));
        } catch (IllegalBlockSizeException illegalBlockSizeExc) {
            throw new EncryptionDecryptionException("Exception while encrypting, due to block size " + illegalBlockSizeExc);
        } catch (BadPaddingException badPaddingExc) {
            throw new EncryptionDecryptionException("Exception while encrypting, due to padding scheme " + badPaddingExc);
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionDecryptionException("Unsupported Encoding for message!");
        }

        return cipherTextInByteArr;
    }
}
