package com.dilaverdemirel.encryption;

import java.security.spec.AlgorithmParameterSpec;

/**
 * @author dilaverdemirel@gmail.com
 *
 */
public class Config<T extends AlgorithmParameterSpec> {
    private int keySize;
    private int initializationVectorSize;
    private int authenticationTagBitLength;
    private String algorithm;
    private String modeOfOperation;
    private String padding;
    private T algorithmParameterSpec;
    private String messageCharset = "UTF-8";

    public String getAlgorithmTransformationString(){
        return new StringBuilder().append(algorithm).append("/").append(modeOfOperation).append("/").append(padding).toString();
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public int getInitializationVectorSize() {
        return initializationVectorSize;
    }

    public void setInitializationVectorSize(int initializationVectorSize) {
        this.initializationVectorSize = initializationVectorSize;
    }

    public int getAuthenticationTagBitLength() {
        return authenticationTagBitLength;
    }

    public void setAuthenticationTagBitLength(int authenticationTagBitLength) {
        this.authenticationTagBitLength = authenticationTagBitLength;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getModeOfOperation() {
        return modeOfOperation;
    }

    public void setModeOfOperation(String modeOfOperation) {
        this.modeOfOperation = modeOfOperation;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public T getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }

    public void setAlgorithmParameterSpec(T algorithmParameterSpec) {
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    public String getMessageCharset() {
        return messageCharset;
    }

    public void setMessageCharset(String messageCharset) {
        this.messageCharset = messageCharset;
    }
}
