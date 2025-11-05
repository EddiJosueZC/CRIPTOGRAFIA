package com.chatseguro.crypto;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class TestCrypto {
    public static void main(String[] args) throws Exception {
        // 1) Simular que el server te dio estos parámetros KDF
        byte[] saltDerive = new byte[16];
        new SecureRandom().nextBytes(saltDerive);
        int iterations = 200_000;

        // 2) Tu "CLAVE DE CHAT" (passphrase PSK)
        String chatKey = "clave-super-secreta";

        // 3) Derivar AES-256 con PBKDF2
        SecretKeySpec aesKey = Kdf.deriveAesKey(chatKey.toCharArray(), saltDerive, iterations);

        // 4) Cifrar
        String mensaje = "hola mundo seguro";
        AesGcm.Box box = AesGcm.encrypt(mensaje.getBytes(StandardCharsets.UTF_8), null, aesKey);

        // 5) Descifrar
        byte[] plain = AesGcm.decrypt(box.nonce, null, box.ct, aesKey);

        // 6) Mostrar resultados
        System.out.println("saltDerive.b64 = " + Base64.getEncoder().encodeToString(saltDerive));
        System.out.println("nonce.b64      = " + Base64.getEncoder().encodeToString(box.nonce));
        System.out.println("ct.b64         = " + Base64.getEncoder().encodeToString(box.ct));
        System.out.println("plaintext      = " + new String(plain, StandardCharsets.UTF_8));
    }
}
