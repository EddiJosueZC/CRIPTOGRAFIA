package com.chatseguro.service;

import com.chatseguro.db.Db;
import java.sql.Connection;
import java.sql.PreparedStatement;

public class MessageService {
    public static void saveEncrypted(long convId, long senderId, byte[] nonce, byte[] aad, byte[] ciphertext) throws Exception {
        try (Connection c = Db.get();
             PreparedStatement st = c.prepareStatement(
                     "INSERT INTO messages(conversation_id, sender_id, nonce, aad, ciphertext) VALUES(?,?,?,?,?)")) {
            st.setLong(1, convId);
            st.setLong(2, senderId);
            st.setBytes(3, nonce);
            st.setBytes(4, aad);
            st.setBytes(5, ciphertext);
            st.executeUpdate();
        }
    }
}
