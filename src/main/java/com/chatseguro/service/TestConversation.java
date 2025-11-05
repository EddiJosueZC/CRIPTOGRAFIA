package com.chatseguro.service;

import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

public class TestConversation {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("=== TestConversation ===");
        System.out.println("1) Crear conversación");
        System.out.println("2) Unirse a conversación");
        System.out.println("3) Ver KDF params");
        System.out.print("Elige: ");
        String opt = sc.nextLine().trim();

        if ("1".equals(opt)) {
            System.out.print("creatorId (usa el id devuelto por TestAuth login): ");
            long creatorId = Long.parseLong(sc.nextLine().trim());
            System.out.print("Título: ");
            String title = sc.nextLine();
            System.out.print("CLAVE DE CHAT (PSK): ");
            String chatKey = sc.nextLine();

            long convId = ConversationService.createConversation(creatorId, title, chatKey);
            System.out.println("✅ Conversación creada con id = " + convId);

        } else if ("2".equals(opt)) {
            System.out.print("convId: ");
            long convId = Long.parseLong(sc.nextLine().trim());
            System.out.print("userId: ");
            long userId = Long.parseLong(sc.nextLine().trim());
            System.out.print("CLAVE DE CHAT (PSK): ");
            String chatKey = sc.nextLine();

            boolean ok = ConversationService.joinConversation(convId, userId, chatKey);
            System.out.println(ok ? "✅ JOIN OK" : "❌ JOIN FAIL");

        } else if ("3".equals(opt)) {
            System.out.print("convId: ");
            long convId = Long.parseLong(sc.nextLine().trim());
            Map<String, Object> kdf = ConversationService.getKdfParams(convId);
            if (kdf == null) {
                System.out.println("❌ No existe esa conversación");
                return;
            }
            byte[] salt = (byte[]) kdf.get("salt_derive");
            int it = (int) kdf.get("iterations");
            System.out.println("iterations = " + it);
            System.out.println("salt_derive.b64 = " + Base64.getEncoder().encodeToString(salt));
        } else {
            System.out.println("Opción inválida.");
        }
    }
}
