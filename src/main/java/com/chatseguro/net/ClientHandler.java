package com.chatseguro.net;

import com.chatseguro.service.AuthService;
import com.chatseguro.service.ConversationService;
import com.chatseguro.service.MessageService;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Map;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final Server server;

    private BufferedReader in;
    private PrintWriter out;

    // Estado del cliente
    private Long userId = null;
    private String username = null;
    private Long conversationId = null;
    private boolean joined = false;

    public ClientHandler(Socket socket, Server server) {
        this.socket = socket;
        this.server = server;
    }

    public boolean isJoined() { return joined; }
    public long getConversationId() { return conversationId == null ? -1 : conversationId; }

    public void sendLine(String line) {
        try { out.println(line); } catch (Exception ignored) {}
    }

    @Override public void run() {
        try {
            in  = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

            out.println("WELCOME ChatSeguro v1 (AES-GCM + PSK) - Comandos: AUTH, JOIN, SEND, QUIT");

            String line;
            while ((line = in.readLine()) != null) {
                String msg = line.trim();
                if (msg.isEmpty()) continue;

                if      (msg.startsWith("AUTH ")) handleAuth(msg.substring(5));
                else if (msg.startsWith("JOIN ")) handleJoin(msg.substring(5));
                else if (msg.startsWith("SEND ")) handleSend(msg.substring(5));
                else if ("QUIT".equalsIgnoreCase(msg)) break;
                else out.println("ERR comando no reconocido");
            }
        } catch (Exception e) {
            System.err.println("[CLIENT ERROR] " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
            server.remove(this);
            System.out.println("[CLIENT] desconectado: " + username);
        }
    }

    private void handleAuth(String args) {
        try {
            String[] p = args.split("\\s+");
            if (p.length < 2) { out.println("AUTH_FAIL"); return; }
            String u = p[0], pass = p[1];
            Long id = AuthService.login(u, pass);
            if (id == null) { out.println("AUTH_FAIL"); return; }
            this.userId = id;
            this.username = u;
            out.println("AUTH_OK " + id);
            System.out.println("[AUTH] " + username + " (" + id + ")");
        } catch (Exception e) {
            out.println("AUTH_FAIL");
        }
    }

    private void handleJoin(String args) {
        if (userId == null) { out.println("JOIN_FAIL not_auth"); return; }
        try {
            String[] p = args.split("\\s+");
            if (p.length < 2) { out.println("JOIN_FAIL"); return; }
            long convId = Long.parseLong(p[0]);
            String chatKey = p[1];

            boolean ok = ConversationService.joinConversation(convId, userId, chatKey);
            if (!ok) { out.println("JOIN_FAIL"); return; }

            Map<String, Object> kdf = ConversationService.getKdfParams(convId);
            byte[] saltDerive = (byte[]) kdf.get("salt_derive");
            int iterations = (int) kdf.get("iterations");

            this.conversationId = convId;
            this.joined = true;

            String saltB64 = Base64.getEncoder().encodeToString(saltDerive);
            out.println("JOIN_OK " + iterations + " " + saltB64);

            System.out.println("[JOIN] user=" + username + " conv=" + convId);
        } catch (Exception e) {
            out.println("JOIN_FAIL");
        }
    }

    private void handleSend(String payload) {
        if (!joined || userId == null || conversationId == null) {
            out.println("ERR not_joined"); return;
        }
        try {
            // formato: base64(nonce):base64(ciphertext)
            String[] parts = payload.split(":", 2);
            if (parts.length != 2) { out.println("ERR bad_format"); return; }

            byte[] nonce = Base64.getDecoder().decode(parts[0]);
            byte[] ct    = Base64.getDecoder().decode(parts[1]);

            // guarda en BD (AAD null por simplicidad)
            MessageService.saveEncrypted(conversationId, userId, nonce, null, ct);

            // retransmite SOLO a la misma conversación
            String wire = "MSG " + username + " " + parts[0] + ":" + parts[1];
            server.broadcastToConversation(conversationId, wire, this);

            // eco al remitente
            out.println(wire);
        } catch (SQLException e) {
            out.println("ERR db");
        } catch (IllegalArgumentException e) {
            out.println("ERR base64");
        } catch (Exception e) {
            out.println("ERR unknown");
        }
    }
}
