package com.microsoft.azure.keyvault.cryptography.algorithms;

import java.security.KeyPair;

import com.microsoft.azure.keyvault.cryptography.ISignatureTransform;

public class Ps512 extends PsBase {
    public final static String ALGORITHM_NAME = "PS512";
    public final static String DIGEST_HASH_NAME = "SHA-512";

    public Ps512() {
        super(ALGORITHM_NAME);
    }
    
    @Override
    public ISignatureTransform createSignatureTransform(KeyPair keyPair) {
        return createSignatureTransform(keyPair, DIGEST_HASH_NAME);
    }
}
