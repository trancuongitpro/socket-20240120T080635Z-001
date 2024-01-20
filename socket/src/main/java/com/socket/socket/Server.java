package com.socket.socket;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class Server {
    private static final int PORT = 8080;
    private static KeyPair keyPair;

    public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyPair = keyGen.generateKeyPair();

            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server is listening on port " + PORT);

            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());

            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

            String encryptedMessage = reader.readLine();
            String decryptedMessage = decrypt(encryptedMessage);
            System.out.println("Received message from client: " + decryptedMessage);

            String response = "clientID said: #" + decryptedMessage;
            String encryptedResponse = encrypt(response);
            writer.write(encryptedResponse);
            writer.newLine();
            writer.flush();

            serverSocket.close();
            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");

        // Ensure keyPair is not null and properly initialized
        if (keyPair == null || keyPair.getPrivate() == null) {
            throw new IllegalArgumentException("KeyPair or private key is not initialized.");
        }

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // Remove non-base64 characters and decode base64 string
        String base64Text = encryptedText.replaceAll("[^a-zA-Z0-9+/=]", "");
        byte[] encryptedBytes = Base64.getDecoder().decode(base64Text);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

}
