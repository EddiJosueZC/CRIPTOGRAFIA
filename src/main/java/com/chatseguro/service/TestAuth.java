package com.chatseguro.service;

import java.sql.SQLIntegrityConstraintViolationException;
import java.util.Scanner;

public class TestAuth {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("=== TestAuth ===");
        System.out.println("1) Registrar usuario");
        System.out.println("2) Login");
        System.out.print("Elige: ");
        String opt = sc.nextLine().trim();

        if ("1".equals(opt)) {
            System.out.print("Nuevo username: ");
            String u = sc.nextLine().trim();
            System.out.print("Password: ");
            String p = sc.nextLine();

            try {
                AuthService.register(u, p);
                System.out.println("✅ Usuario registrado: " + u);
            } catch (SQLIntegrityConstraintViolationException dup) {
                System.out.println("⚠️  Ese username ya existe.");
            }
        } else if ("2".equals(opt)) {
            System.out.print("Username: ");
            String u = sc.nextLine().trim();
            System.out.print("Password: ");
            String p = sc.nextLine();

            Long id = AuthService.login(u, p);
            if (id != null) {
                System.out.println("✅ Login OK. userId=" + id);
            } else {
                System.out.println("❌ Login FAIL (usuario o password incorrectos)");
            }
        } else {
            System.out.println("Opción inválida.");
        }
    }
}
