package com.chatseguro.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AesGcm {
    public static final int NONCE_LEN = 12;  // recomendado para GCM
    private static final int TAG_BITS = 128; // 128 típicamente

    public static class Box {
        public final byte[] nonce, ct; // ct incluye el tag GCM al final
        public Box(byte[] n, byte[] c) { nonce = n; ct = c; }
    }

    public static Box encrypt(byte[] plaintext, byte[] aad, SecretKeySpec key) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (aad != null) cipher.updateAAD(aad);

        byte[] ct = cipher.doFinal(plaintext);
        return new Box(nonce, ct);
    }

    public static byte[] decrypt(byte[] nonce, byte[] aad, byte[] ct, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(ct);
    }
}
