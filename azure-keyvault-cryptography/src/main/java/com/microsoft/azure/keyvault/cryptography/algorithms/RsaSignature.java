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
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import com.google.common.primitives.Bytes;
import com.microsoft.azure.keyvault.cryptography.AsymmetricSignatureAlgorithm;
import com.microsoft.azure.keyvault.cryptography.ISignatureTransform;
import com.microsoft.azure.keyvault.cryptography.Strings;

public abstract class RsaSignature extends AsymmetricSignatureAlgorithm {

    private static final BigInteger twoFiveSix = new BigInteger("256");
    private static final byte[] sha256Prefix = new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48,
            0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

    protected RsaSignature(String name) {
        super(name);
    }

    protected int getOctetLength(int bits) {
        return (bits % 8 > 0) ? bits >> 3 + 1 : bits >> 3;
    }

    /*
     * See https://tools.ietf.org/html/rfc3447#section-4.2
     */
    protected BigInteger OS2IP(byte[] x) {

        if (x == null || x.length == 0) {
            throw new IllegalArgumentException("x");
        }

        return new BigInteger(1, x);
    }

    /*
     * See https://tools.ietf.org/html/rfc3447#section-4.1
     */
    protected byte[] I2OSP(BigInteger x, int xLen) {

        if (x == null) {
            throw new IllegalArgumentException("x");
        }

        if (xLen <= 0) {
            throw new IllegalArgumentException("xLen");
        }

        if (x.compareTo(twoFiveSix.pow(xLen)) == 1) {
            throw new IllegalArgumentException("integer too large");
        }

        // Even if x is less than 256^xLen, sometiems x.toByteArray() returns 257 bytes
        // with leading zero
        byte[] bigEndianBytes = x.toByteArray();
        byte[] bytes;
        if (bigEndianBytes.length == 257 && bigEndianBytes[0] == 0) {
            bytes = Arrays.copyOfRange(bigEndianBytes, 1, 257);
        } else {
            bytes = bigEndianBytes;
        }

        if (bytes.length > xLen) {
            throw new IllegalArgumentException("integer too large");
        }

        byte[] result = new byte[xLen];

        System.arraycopy(bytes, 0, result, xLen - bytes.length, bytes.length);

        return result;
    }

    /*
     * See https://tools.ietf.org/html/rfc3447#section-5.2.1
     */
    protected BigInteger RSASP1(RSAPrivateKey K, BigInteger m) {

        if (K == null) {
            throw new IllegalArgumentException("K");
        }

        if (m == null) {
            throw new IllegalArgumentException("m");
        }

        BigInteger n = K.getModulus();
        BigInteger d = K.getPrivateExponent();

        if (m.compareTo(BigInteger.ONE) == -1 || m.compareTo(n) != -1) {
            throw new IllegalArgumentException("message representative out of range");
        }

        return m.modPow(d, n);
    }

    /*
     * See https://tools.ietf.org/html/rfc3447#section-5.2.2
     */
    protected BigInteger RSAVP1(RSAPublicKey K, BigInteger s) {

        if (K == null) {
            throw new IllegalArgumentException("K");
        }

        if (s == null) {
            throw new IllegalArgumentException("s");
        }
        BigInteger n = K.getModulus();
        BigInteger e = K.getPublicExponent();

        if (s.compareTo(BigInteger.ONE) == -1 || s.compareTo(n) != -1) {
            throw new IllegalArgumentException("message representative out of range");
        }

        return s.modPow(e, n);
    }
    
    /**
     * See https://tools.ietf.org/html/rfc3447#section-9.1.1
     * 
     * @param mHash the hashed message (hashed with the corresponding digest: i.e., SHA-256 for PS256, SHA-384 for PS384, SHA-512 for PS512 
     * @param emBits the maximal bit length of the integer OS2IP(EM)
     * @param messageDigest the messageDigest (or hash) that corresponds to the algorithm
     * @return
     */
    protected byte[] EMSA_PSS_ENCODE_HASH(byte[] mHash, int emBits, MessageDigest messageDigest) {

        // Let mHash = Hash(M), an octet string of length hLen.
        // function takes in the mHash.

        // salt length for the service corresponds to the digest length, which is the hash length / 8
        int sLen = messageDigest.getDigestLength();
        int hLen = mHash.length;
        int emLen = (int) Math.ceil(emBits / 8.0);

        // If emLen < hLen + sLen + 2, output "encoding error" and stop.
        if (emLen < (hLen + sLen + 2)) {
            throw new IllegalArgumentException("encoding error");
        }

        // Generate a random octet string salt of length sLen; if sLen = 0,
        // then salt is the empty string.

        byte[] salt = new byte[sLen];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(salt);

        // 5. Let
        // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
        // M' is an octet string of length 8 + hLen + sLen with eight
        // initial zero octets.
        messageDigest.update(new byte[8]);
        messageDigest.update(mHash);
        messageDigest.update(salt);

        // 6. Let H = Hash(M'), an octet string of length hLen.
        byte[] H = messageDigest.digest();

        // 7. Generate an octet string PS consisting of emLen - sLen - hLen - 2
        // zero octets. The length of PS may be 0.
        byte[] PS = new byte[emLen - sLen - hLen - 2];

        // 8. Let DB = PS || 0x01 || salt; DB is an octet string of length
        // emLen - hLen - 1.

        byte[] DB = new byte[emLen - hLen - 1];

        System.arraycopy(PS, 0, DB, 0, emLen - sLen - hLen - 2);
        DB[emLen - sLen - hLen - 2] = (byte) 0x01;
        System.arraycopy(salt, 0, DB, emLen - sLen - hLen - 1, sLen);

        // 9. Let dbMask = MGF(H, emLen - hLen - 1).
        byte[] dbMask = MGF(H, emLen - hLen - 1, messageDigest);

        byte[] maskedDB = new byte[Math.min(DB.length, dbMask.length)];

        // 10. Let maskedDB = DB \xor dbMask.
        for (int i = 0; i < maskedDB.length; i++) {
            maskedDB[i] = (byte) (((int) DB[i]) ^ ((int) dbMask[i]));
        }

        // 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
        // maskedDB to zero.
        int bitMask = 0x000000FF >>> (8 * emLen - emBits);
        maskedDB[0] &= (byte) bitMask;

        // 12. Let EM = maskedDB || H || 0xbc.
        return Bytes.concat(maskedDB, H, new byte[] { (byte) 0xbc });

    }
    
    /**
     * See https://tools.ietf.org/html/rfc3447#section-9.1.2
     * 
     * @param mHash the hashed message (hashed with the corresponding digest: i.e., SHA-256 for PS256, SHA-384 for PS384, SHA-512 for PS512
     * @param EM encoded message, an octet string of emLen = \ceil(emBits/8)
     * @param emBits maximal bit length of the integer OS2IP(EM)
     * @param messageDigest the messageDigest that corresponds to the algorithm (see above)
     * @return true if output consistent with algorithm, false otherwise
     */
    protected boolean EMSA_PSS_VERIFY(byte[] mHash, byte[] EM, int emBits, MessageDigest messageDigest) {

        // salt length for the service corresponds to the digest length, which is the hash length / 8
        int sLen = messageDigest.getDigestLength();
        int hLen = mHash.length;
        int emLen = (int) Math.ceil(emBits / 8.0);

        // 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
        if (emLen < hLen + sLen + 2) {
            return false;
        }

        // 4. If the rightmost octet of EM does not have hexadecimal value
        // 0xbc, output "inconsistent" and stop.
        if (EM[EM.length - 1] != (byte) 0xbc) {
            return false;
        }

        // 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
        // let H be the next hLen octets.
        byte[] maskedDB = Arrays.copyOfRange(EM, 0, emLen - hLen - 1);
        byte[] H = Arrays.copyOfRange(EM, emLen - hLen - 1, emLen - 1);

        // 6. If the leftmost 8emLen - emBits bits of the leftmost octet in
        // maskedDB are not all equal to zero, output "inconsistent" and
        // stop.
        byte mask = 0x00;
        for (int i = 0; i < (8 * emLen - emBits); i++) {
            mask = (byte) (mask | (1 << i));
            if ((maskedDB[0] & mask) != 0) {
                return false;
            }
            mask = 0x00;
        }

        // 7. Let dbMask = MGF(H, emLen - hLen - 1).
        byte[] dbMask = MGF(H, emLen - hLen - 1, messageDigest);

        // 8. Let DB = maskedDB \xor dbMask.
        byte[] DB = new byte[Math.min(maskedDB.length, dbMask.length)];
        for (int i = 0; i < maskedDB.length; i++) {
            DB[i] = (byte) (maskedDB[i] ^ dbMask[i]);
        }

        // 9. Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
        // to zero.

        int bitMask = 0x000000FF >> (8 * emLen - emBits + 1);
        DB[0] &= bitMask;

        // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
        // or if the octet at position emLen - hLen - sLen - 1 (the leftmost
        // position is "position 1") does not have hexadecimal value 0x01,
        // output "inconsistent" and stop.
        for (int i = 0; i < (emLen - hLen - sLen - 2); i++) {
            if (DB[i] != 0) {
                return false;
            }
        }

        if (DB[emLen - hLen - sLen - 2] != (byte) 0x01) {
            return false;
        }

        // 11. Let salt be the last sLen octets of DB.
        byte[] salt = Arrays.copyOfRange(DB, DB.length - sLen, DB.length);

        // 12. Let
        // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
        // M' is an octet string of length 8 + hLen + sLen with eight
        // initial zero octets.
        // 13. Let H' = Hash(M'), an octet string of length hLen.

        // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
        messageDigest.update(new byte[8]);
        messageDigest.update(mHash);
        return Arrays.equals(H, messageDigest.digest(salt));
    }
    
    /**
     * See https://tools.ietf.org/html/rfc3447#appendix-B.2.1
     * 
     * @param mgfSeed seed from which mask is generated, an octet string
     * @param maskLen intended length in octets of the mask, at most 2^32 hLen
     * @param digest messageDigest - the hash function corresponding to the length of the hash
     * @return mask, an octet string of length maskLen
     */
    protected byte[] MGF(byte[] mgfSeed, int maskLen, MessageDigest digest) {

        if (maskLen > Math.pow(2, 32) * 32) {
            throw new IllegalArgumentException("mask too long");
        }
        
        int hashCount = (int) (Math.ceil(maskLen * 1.0 / digest.getDigestLength()) - 1);
        byte[] mask = new byte[0];

        // 3.For counter from 0 to \lceil{l / hLen}\ceil-1, do the following:
        for (int i = 0; i <= hashCount; i++) {
            digest.update(mgfSeed);

            // a.Convert counter to an octet string C of length 4 with the primitive
            // I2OSP: C = I2OSP (counter, 4)
            digest.update(I2OSP(BigInteger.valueOf(i), 4));

            // b.Concatenate the hash of the seed Z and C to the octet string T: T =
            // T || Hash (Z || C)
            byte[] hash = digest.digest();
            mask = Bytes.concat(mask, hash);
        }
        
        byte[] output = new byte[maskLen];
        System.arraycopy(mask, 0, output, 0, output.length);
        return output;
    }

    /*
     * See https://tools.ietf.org/html/rfc3447#section-9.2
     */
    protected byte[] EMSA_PKCS1_V1_5_ENCODE(byte[] m, int emLen, String algorithm) throws NoSuchAlgorithmException {

        // Check m
        if (m == null || m.length == 0) {
            throw new IllegalArgumentException("m");
        }

        MessageDigest messageDigest = null;

        // Check algorithm
        if (Strings.isNullOrWhiteSpace(algorithm)) {
            throw new IllegalArgumentException("algorithm");
        }

        // Only supported algorithms
        if (algorithm.equals("SHA-256")) {

            // Initialize digest
            messageDigest = MessageDigest.getInstance("SHA-256");
        } else {
            throw new IllegalArgumentException("algorithm");
        }

        // Hash the message
        byte[] digest = messageDigest.digest(m);

        // Construct T, the DER encoded DigestInfo structure
        return EMSA_PKCS1_V1_5_ENCODE_HASH(digest, emLen, algorithm);
    }

    /*
     * See https://tools.ietf.org/html/rfc3447#section-9.2
     */
    protected byte[] EMSA_PKCS1_V1_5_ENCODE_HASH(byte[] h, int emLen, String algorithm)
            throws NoSuchAlgorithmException {

        // Check m
        if (h == null || h.length == 0) {
            throw new IllegalArgumentException("m");
        }

        byte[] algorithmPrefix = null;

        // Check algorithm
        if (Strings.isNullOrWhiteSpace(algorithm)) {
            throw new IllegalArgumentException("algorithm");
        }

        // Only supported algorithms
        if (algorithm.equals("SHA-256")) {

            // Initialize prefix and digest
            algorithmPrefix = sha256Prefix;

            if (h.length != 32) {
                throw new IllegalArgumentException("h is incorrect length for SHA-256");
            }
        } else {
            throw new IllegalArgumentException("algorithm");
        }

        // Construct T, the DER encoded DigestInfo structure
        byte[] T = new byte[algorithmPrefix.length + h.length];

        System.arraycopy(algorithmPrefix, 0, T, 0, algorithmPrefix.length);
        System.arraycopy(h, 0, T, algorithmPrefix.length, h.length);

        if (emLen < T.length + 11) {
            throw new IllegalArgumentException("intended encoded message length too short");
        }

        // Construct PS
        byte[] PS = new byte[emLen - T.length - 3];

        for (int i = 0; i < PS.length; i++)
            PS[i] = (byte) 0xff;

        // Construct EM
        byte[] EM = new byte[PS.length + T.length + 3];

        EM[0] = 0x00;
        EM[1] = 0x01;
        EM[PS.length + 2] = 0x00;

        System.arraycopy(PS, 0, EM, 2, PS.length);
        System.arraycopy(T, 0, EM, PS.length + 3, T.length);

        return EM;
    }

    public abstract ISignatureTransform createSignatureTransform(KeyPair keyPair);
}
