package com.microsoft.azure.keyvault.cryptography.algorithms;

import java.security.KeyPair;

import com.microsoft.azure.keyvault.cryptography.ISignatureTransform;

public class Ps384 extends PsBase {
    
    public final static String ALGORITHM_NAME = "PS384";
    public final static String DIGEST_HASH_NAME = "SHA-384";

    public Ps384() {
        super(ALGORITHM_NAME);
    }
    
    @Override
    public ISignatureTransform createSignatureTransform(KeyPair keyPair) {
        return createSignatureTransform(keyPair, DIGEST_HASH_NAME);
    }
    
}
