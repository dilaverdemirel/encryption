package com.dilaverdemirel.encryption;

import java.security.SecureRandom;

/**
 * @author dilaverdemirel@gmail.com
 */
public class EncryptionUtil {
    private static SecureRandom secRandom = new SecureRandom();

    public static byte[] getInitializationVector(int initializationVectorSize) {
        // Generating IV
        byte iv[] = new byte[initializationVectorSize];
        secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding
        return iv;
    }
}
