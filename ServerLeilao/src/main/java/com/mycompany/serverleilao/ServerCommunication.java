/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.serverleilao;

import com.mycompany.certificateauthority.CAregisters;
import com.mycompany.view.AuctionPanel;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import org.json.JSONObject;

/**
 *
 * @author nandones
 */
public class ServerCommunication {

    public static ServerSocket serverSocket;
    public static CAregisters ca = new CAregisters();

    public static void main(String[] args) {

    }
    /**
     * this method requires to already have the multicast and handshake server adresses and ports values.
     * @param serverSocket 
     */
    public static void receiveAndProcessJoinRequest(ServerSocket serverSocket) {
        try {
            System.out.println("Waiting for client connection...");
            // Accept the client connection
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected!");

            // Create input and output streams for communication
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Read the incoming JSON message
            String jsonMessage = in.readLine();
            System.out.println("Received JSON: " + jsonMessage);

            // Parse the JSON message
            JSONObject json = new JSONObject(jsonMessage);

            // Extract the fields from the JSON
            String cpf = json.getString("CPF");
            String signatureBase64 = json.getString("signature");
            String text = json.getString("text");

            // Log the extracted fields
            System.out.println("CPF: " + cpf);
            System.out.println("Signature: " + signatureBase64);
            System.out.println("Text: " + text);

            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            String clientPublicKeyBase64 = ca.returnPublicKeyBase64(cpf);
            System.out.println(clientPublicKeyBase64);
            PublicKey clientPublicKey = ServerCryptoUtils.convertBase64StringToPublicKey(clientPublicKeyBase64);
            boolean authentication = ServerCryptoUtils.verifySignature(text, signatureBytes, clientPublicKey);

            if (authentication) {
                text = "user authenticated.";

                signatureBytes = ServerCryptoUtils.signMessage(text, ServerAuction.SERVER_PRIVATE_KEY_BYTES);
                signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
                //Secret Key encoded with client public key.
                String encodedSecretKey = ServerCryptoUtils.encryptWithRSA(ServerAuction.SECRET_KEY_BASE_64, clientPublicKey);
                JSONObject response = new JSONObject();
                response.put("adress", ServerAuction.multicastAddress);//String
                response.put("port", ServerAuction.multicastPort);//int
                response.put("secretKey", encodedSecretKey);//String in base64, encoded with client public key.
                response.put("text", text);
                response.put("signature", signatureBase64);
                out.println(response.toString());
            } else {
                out.println("user not authenticated.");
            }
            // Close the streams and socket
            System.out.println("");
            System.out.println("secret key: /n"+ ServerAuction.SECRET_KEY_BASE_64);
            in.close();
            out.close();
            clientSocket.close();
            System.out.println("Connection closed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
