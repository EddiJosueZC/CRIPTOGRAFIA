package com.chatseguro.net;

import com.chatseguro.crypto.AesGcm;
import com.chatseguro.crypto.Kdf;

import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class ClientMain {

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        // ===== 1) CONEXIÓN (con reintentos) =====
        String host;
        int port;
        Socket socket = null;
        BufferedReader in = null;
        PrintWriter out = null;

        while (true) {
            System.out.print("Servidor (host) [localhost]: ");
            System.out.flush();
            host = sc.nextLine().trim();
            if (host.isBlank()) host = "localhost";

            System.out.print("Puerto [5000]: ");
            System.out.flush();
            String p = sc.nextLine().trim();
            if (p.isBlank()) p = "5000";

            try {
                port = Integer.parseInt(p);
                socket = new Socket(host, port);
                in  = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
                System.out.println("[CLIENT] Conectado a " + host + ":" + port);
                break;
            } catch (Exception e) {
                System.out.println("❌ No se pudo conectar (" + e.getMessage() + "). Intenta de nuevo.");
            }
        }

        // lee banner de bienvenida del server (si existe)
        socket.setSoTimeout(0); // bloqueante
        try {
            if (in.ready()) System.out.println(in.readLine());
        } catch (IOException ignored) {}

        // ===== 2) AUTH (con reintentos) =====
        String authResp;
        while (true) {
            System.out.print("Usuario: ");
            System.out.flush();
            String username = sc.nextLine().trim();

            System.out.print("Password: ");
            System.out.flush();
            String password = sc.nextLine().trim();

            out.println("AUTH " + username + " " + password);
            authResp = in.readLine(); // bloqueante

            if (authResp != null && authResp.startsWith("AUTH_OK")) {
                System.out.println("[OK] " + authResp);
                break;
            }
            System.out.println("❌ Credenciales inválidas. Intenta de nuevo.\n");
        }

        // ===== 3) JOIN (con reintentos) =====
        String joinResp;
        String convId, chatKey;
        int iterations;
        byte[] saltDerive;
        final SecretKeySpec[] aesKeyHolder = new SecretKeySpec[1];

        while (true) {
            System.out.print("👉 Inserte el ID de conversación: ");
            System.out.flush();
            convId = sc.nextLine().trim();

            System.out.print("🔑 Inserte la CLAVE DE CHAT (PSK): ");
            System.out.flush();
            chatKey = sc.nextLine();

            out.println("JOIN " + convId + " " + chatKey);
            joinResp = in.readLine(); // bloqueante

            if (joinResp != null && joinResp.startsWith("JOIN_OK")) {
                String[] j = joinResp.split("\\s+");
                iterations = Integer.parseInt(j[1]);
                saltDerive = Base64.getDecoder().decode(j[2]);
                SecretKeySpec aesKey = Kdf.deriveAesKey(chatKey.toCharArray(), saltDerive, iterations);
                aesKeyHolder[0] = aesKey;
                System.out.println("[JOIN] Conectado. Escriba mensajes. Use /quit para salir.");
                break;
            }
            System.out.println("❌ No se pudo unir (convId/PSK incorrectos). Intenta de nuevo.\n");
        }

        // ===== 4) LECTOR DE MENSAJES (se inicia SOLO tras JOIN_OK) =====
        BufferedReader finalIn = in;
        Thread reader = new Thread(() -> {
            try {
                String line;
                while ((line = finalIn.readLine()) != null) {
                    if (line.startsWith("MSG ")) {
                        String[] p = line.split("\\s+", 3);
                        if (p.length >= 3 && aesKeyHolder[0] != null) {
                            String sender = p[1];
                            String[] nc = p[2].split(":", 2);
                            byte[] nonce = Base64.getDecoder().decode(nc[0]);
                            byte[] ct    = Base64.getDecoder().decode(nc[1]);
                            try {
                                byte[] pt = AesGcm.decrypt(nonce, null, ct, aesKeyHolder[0]);
                                System.out.println(sender + ": " + new String(pt, StandardCharsets.UTF_8));
                            } catch (Exception e) {
                                System.out.println(sender + ": [no se pudo descifrar: " + e.getMessage() + "]");
                            }
                        } else {
                            System.out.println(line);
                        }
                    } else {
                        System.out.println(line);
                    }
                }
            } catch (IOException ignored) {}
        });
        reader.setDaemon(true);
        reader.start();

        // ===== 5) ENVÍO DE MENSAJES =====
        while (true) {
            String msg = sc.nextLine();
            if ("/quit".equalsIgnoreCase(msg)) { out.println("QUIT"); break; }
            if (msg.isBlank()) continue;
            try {
                AesGcm.Box box = AesGcm.encrypt(msg.getBytes(StandardCharsets.UTF_8), null, aesKeyHolder[0]);
                String wire = "SEND " + Base64.getEncoder().encodeToString(box.nonce) + ":" +
                        Base64.getEncoder().encodeToString(box.ct);
                out.println(wire);
            } catch (Exception e) {
                System.out.println("Error cifrando: " + e.getMessage());
            }
        }

        try { socket.close(); } catch (IOException ignored) {}
        System.out.println("[CLIENT] Bye!");
    }
}
