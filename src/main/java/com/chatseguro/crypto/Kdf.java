package com.chatseguro.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Kdf {

    // Deriva 32 bytes (AES-256) desde passphrase + saltDerive con PBKDF2-HMAC-SHA256
    public static SecretKeySpec deriveAesKey(char[] passphrase, byte[] saltDerive, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase, saltDerive, iterations, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Genera verificador (hash) para comprobar la passphrase PSK (con salt_auth)
    public static byte[] pskVerifier(char[] passphrase, byte[] saltAuth, int iterations, int outLenBytes) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase, saltAuth, iterations, outLenBytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    // Comparación en tiempo constante (evita filtraciones por tiempo)
    public static boolean constantTimeEq(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }
}
