package com.chatseguro.net;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class Server {
    private final int port;
    private final Set<ClientHandler> clients = Collections.synchronizedSet(new HashSet<>());

    public Server(int port) {
        this.port = port;
    }

    public void start() throws Exception {
        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.println("[SERVER] Escuchando en puerto " + port);
            while (true) {
                Socket s = ss.accept();
                ClientHandler h = new ClientHandler(s, this);
                clients.add(h);
                new Thread(h, "client-" + s.getRemoteSocketAddress()).start();
            }
        }
    }

    public void remove(ClientHandler h) {
        clients.remove(h);
    }

    /**
     * Retransmite solo a clientes de la misma conversación
     */
    public void broadcastToConversation(long conversationId, String line, ClientHandler exclude) {
        synchronized (clients) {
            for (ClientHandler c : clients) {
                if (c != exclude && c.isJoined() && c.getConversationId() == conversationId) {
                    c.sendLine(line);
                }
            }
        }
    }
}