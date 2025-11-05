package com.chatseguro.service;

import com.chatseguro.crypto.Kdf;
import com.chatseguro.db.Db;

import java.security.SecureRandom;
import java.sql.*;

public class AuthService {

    private static final SecureRandom RNG = new SecureRandom();
    // Iteraciones PBKDF2 para hash de contraseñas de usuario
    private static final int USER_PBKDF2_ITERATIONS = 200_000;

    /** Registra un usuario nuevo.
     *  Lanza SQLIntegrityConstraintViolationException si el username ya existe.
     */
    public static void register(String username, String password) throws Exception {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);

        // 64 bytes de salida (PBKDF2-HMAC-SHA256)
        byte[] hash = Kdf.pskVerifier(password.toCharArray(), salt, USER_PBKDF2_ITERATIONS, 64);

        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement(
                     "INSERT INTO users(username, pass_hash, pass_salt) VALUES(?,?,?)")) {
            st.setString(1, username);
            st.setBytes(2, hash);
            st.setBytes(3, salt);
            st.executeUpdate();
        }
    }

    /** Devuelve el id del usuario si la contraseña es correcta; si no, null. */
    public static Long login(String username, String password) throws Exception {
        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement(
                     "SELECT id, pass_hash, pass_salt FROM users WHERE username=?")) {

            st.setString(1, username);
            try (ResultSet rs = st.executeQuery()) {
                if (!rs.next()) return null;

                long id = rs.getLong("id");
                byte[] salt = rs.getBytes("pass_salt");
                byte[] hash = rs.getBytes("pass_hash");

                byte[] cand = Kdf.pskVerifier(password.toCharArray(), salt, USER_PBKDF2_ITERATIONS, 64);
                return Kdf.constantTimeEq(cand, hash) ? id : null;
            }
        }
    }

    /** Utilidad: obtener id por username (o null si no existe). */
    public static Long getUserId(String username) throws Exception {
        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement("SELECT id FROM users WHERE username=?")) {
            st.setString(1, username);
            try (ResultSet rs = st.executeQuery()) {
                if (!rs.next()) return null;
                return rs.getLong("id");
            }
        }
    }
}
