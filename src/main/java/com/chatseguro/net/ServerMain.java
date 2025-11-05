package com.chatseguro.net;

public class ServerMain {
    public static void main(String[] args) throws Exception {
        int port = 5000; // puedes cambiarlo si quieres
        new Server(port).start();
    }
}
