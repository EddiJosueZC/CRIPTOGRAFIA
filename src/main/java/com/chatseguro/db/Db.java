package com.chatseguro.db;

import java.sql.Connection;
import java.sql.DriverManager;

public class Db {

    // Configuración para conectar con MariaDB (XAMPP)
    private static final String URL  = "jdbc:mariadb://127.0.0.1:3306/chatdb";
    private static final String USER = "chatuser";
    private static final String PASS = "chatpass123";

    // Método para obtener la conexión
    public static Connection get() throws Exception {
        return DriverManager.getConnection(URL, USER, PASS);
    }

    // Método de prueba para verificar conexión
    public static void main(String[] args) {
        try (Connection conn = get()) {
            System.out.println("✅ Conexión exitosa a la base de datos!");
        } catch (Exception e) {
            System.err.println("❌ Error al conectar: " + e.getMessage());
        }
    }
}
