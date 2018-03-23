package com.microsoft.azure.keyvault.cryptography.algorithms;

import java.security.KeyPair;
import java.security.Provider;

import com.microsoft.azure.keyvault.cryptography.ISignatureTransform;

public class Es512 extends Ecdsa {
	public final static String ALGORITHM_NAME = "SHA512withECDSA";
	
	public Es512() {
		super(ALGORITHM_NAME);
	}
	
	protected ISignatureTransform createSignatureTransform(KeyPair key, Provider provider) {
		return createSignatureTransform(key, ALGORITHM_NAME, provider);
	}
}
