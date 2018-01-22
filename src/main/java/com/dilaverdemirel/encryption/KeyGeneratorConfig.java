package com.dilaverdemirel.encryption;

/**
 * @author dilaverdemirel@gmail.com
 */
public class KeyGeneratorConfig {
    private EncDecType encDecType;
    private int keySize;
    private String algorithm;

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public EncDecType getEncDecType() {
        return encDecType;
    }

    public void setEncDecType(EncDecType encDecType) {
        this.encDecType = encDecType;
    }

    public enum EncDecType {
        symmetric,asymmetric
    }
}
