package com.chatseguro.service;

import com.chatseguro.crypto.Kdf;
import com.chatseguro.db.Db;

import java.security.SecureRandom;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class ConversationService {
    private static final SecureRandom RNG = new SecureRandom();

    /** Crea una conversación con su CLAVE DE CHAT (PSK) y devuelve el ID. */
    public static long createConversation(long creatorId, String title, String chatKey) throws Exception {
        try (Connection c = Db.get()) {
            c.setAutoCommit(false);
            try {
                // 1. Crear la conversación
                long convId;
                try (PreparedStatement st = c.prepareStatement(
                        "INSERT INTO conversations(title, created_by) VALUES(?,?)",
                        Statement.RETURN_GENERATED_KEYS)) {
                    st.setString(1, title);
                    st.setLong(2, creatorId);
                    st.executeUpdate();
                    try (ResultSet gk = st.getGeneratedKeys()) {
                        gk.next();
                        convId = gk.getLong(1);
                    }
                }

                // 2. Generar parámetros de seguridad
                byte[] saltAuth = new byte[16]; RNG.nextBytes(saltAuth);
                byte[] saltDerive = new byte[16]; RNG.nextBytes(saltDerive);
                int iterations = 200_000;

                // 3. Crear hash verificable del PSK
                byte[] pskHash = Kdf.pskVerifier(chatKey.toCharArray(), saltAuth, iterations, 64);

                // 4. Guardar el PSK
                try (PreparedStatement st = c.prepareStatement(
                        "INSERT INTO conversation_psk(conversation_id, psk_hash, salt_auth, salt_derive, iterations) VALUES(?,?,?,?,?)")) {
                    st.setLong(1, convId);
                    st.setBytes(2, pskHash);
                    st.setBytes(3, saltAuth);
                    st.setBytes(4, saltDerive);
                    st.setInt(5, iterations);
                    st.executeUpdate();
                }

                // 5. Añadir al creador como miembro
                try (PreparedStatement st = c.prepareStatement(
                        "INSERT INTO conversation_members(conversation_id, user_id) VALUES(?,?)")) {
                    st.setLong(1, convId);
                    st.setLong(2, creatorId);
                    st.executeUpdate();
                }

                c.commit();
                return convId;
            } catch (Exception e) {
                c.rollback();
                throw e;
            }
        }
    }

    /** Verifica la CLAVE DE CHAT y une al usuario si es correcta. */
    public static boolean joinConversation(long convId, long userId, String chatKey) throws Exception {
        byte[] pskHash, saltAuth;
        int iterations;

        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement(
                     "SELECT psk_hash, salt_auth, iterations FROM conversation_psk WHERE conversation_id=?")) {
            st.setLong(1, convId);
            try (ResultSet rs = st.executeQuery()) {
                if (!rs.next()) return false;
                pskHash = rs.getBytes("psk_hash");
                saltAuth = rs.getBytes("salt_auth");
                iterations = rs.getInt("iterations");
            }
        }

        byte[] cand = Kdf.pskVerifier(chatKey.toCharArray(), saltAuth, iterations, 64);
        if (!Kdf.constantTimeEq(cand, pskHash)) return false;

        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement(
                     "INSERT IGNORE INTO conversation_members(conversation_id, user_id) VALUES(?,?)")) {
            st.setLong(1, convId);
            st.setLong(2, userId);
            st.executeUpdate();
        }
        return true;
    }

    /** Devuelve parámetros para derivar clave AES (salt_derive + iteraciones). */
    public static Map<String, Object> getKdfParams(long convId) throws Exception {
        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement(
                     "SELECT salt_derive, iterations FROM conversation_psk WHERE conversation_id=?")) {
            st.setLong(1, convId);
            try (ResultSet rs = st.executeQuery()) {
                if (!rs.next()) return null;
                Map<String, Object> map = new HashMap<>();
                map.put("salt_derive", rs.getBytes("salt_derive"));
                map.put("iterations", rs.getInt("iterations"));
                return map;
            }
        }
    }
}
