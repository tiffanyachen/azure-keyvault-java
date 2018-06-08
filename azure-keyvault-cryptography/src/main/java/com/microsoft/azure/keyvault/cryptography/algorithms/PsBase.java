/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.keyvault.cryptography.algorithms;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.security.Signature;

import com.microsoft.azure.keyvault.cryptography.ByteExtensions;
import com.microsoft.azure.keyvault.cryptography.ISignatureTransform;

/**
 *
 */
public abstract class PsBase extends RsaSignature {

    protected PsBase(String name) {
        super(name);
    }

    class PsBaseSignatureTransform implements ISignatureTransform {

        private final KeyPair _keyPair;
        private final int _emLen;
        private final int _modBits;
        private final String _digestName;

        PsBaseSignatureTransform(KeyPair keyPair, String digestName) {
            _keyPair = keyPair;
            BigInteger modulus = ((RSAPublicKey) _keyPair.getPublic()).getModulus();
            _emLen = getOctetLength(modulus.bitLength());
            _modBits = ((RSAPublicKey) _keyPair.getPublic()).getModulus().bitLength();
            _digestName = digestName;
        }

        @Override
        public byte[] sign(byte[] digest) throws NoSuchAlgorithmException {

            if (_keyPair.getPrivate() == null) {
                throw new IllegalArgumentException("Keypair must have private key to for signing.");
            }

            // Construct the encoded message
            // Apply the EMSA-PSS encoding operation (Section
            // 9.1.1) to the message M to produce an encoded message EM of length
            // \ceil ((modBits - 1)/8) octets such that the bit length of the
            // integer OS2IP (EM) (see Section 4.2) is at most modBits - 1, where
            // modBits is the length in bits of the RSA modulus n:
            MessageDigest messageDigest = MessageDigest.getInstance(_digestName);
            byte[] EM = EMSA_PSS_ENCODE_HASH(digest, _modBits - 1, messageDigest);

            // Convert to integer message
            BigInteger m = OS2IP(EM);

            // RSASP1(s)
            m = RSASP1((RSAPrivateKey) _keyPair.getPrivate(), m);

            // Convert to octet sequence
            return I2OSP(m, _emLen);
        }

        @Override
        public boolean verify(byte[] digest, byte[] signature) throws NoSuchAlgorithmException {

            if (signature.length != _emLen) {
                throw new IllegalArgumentException("invalid signature length");
            }

            // Convert to integer signature
            BigInteger s = OS2IP(signature);

            // Convert integer message
            BigInteger m = RSAVP1((RSAPublicKey) _keyPair.getPublic(), s);

            byte[] EM = I2OSP(m, _emLen);

            MessageDigest messageDigest = MessageDigest.getInstance(_digestName);
            return EMSA_PSS_VERIFY(digest, EM, _modBits, messageDigest);
        }

    }

    public ISignatureTransform createSignatureTransform(KeyPair keyPair, String digestString) {
        return new PsBaseSignatureTransform(keyPair, digestString);
    }
}
