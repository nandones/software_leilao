package com.mycompany.clientleilao;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import org.json.JSONObject;

/**
 *
 * @author nandones
 */
public class ClientCommunicationUtils {

    /*
    stateless
    handshake
     */
    /**
     *
     * @param CPF (String)
     * @param plainText (String)
     * @param signature (String) in base64
     * @param serverAdress (String)
     * @param serverPort (int)
     * @return responseJson (String), containing Adress, Port and SecretKey of
     * multicast, or null, if it couldn't connect to the server.
     */
    public static String sendRequestToServer(String CPF, String plainText, String signature, String serverAdress, int serverPort) {

        try {
            // Creates a socket that connects to the server socket at the specified Address and Port.
            Socket socket = new Socket(serverAdress, serverPort);
            System.out.println("Connected to the server!");

            // Creates an output stream to send data to the server
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            // Creates an input stream to receive the response from the server
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Converts the data into a JSON string using a helper method
            String json = createJoinRequestJson(CPF, plainText, signature);

            System.out.println("Sending payload to the server as JSON...");
            out.println(json);

            // Reads the response from the server (assuming it's a JSON string in a single line)
            String responseJson = in.readLine();
            System.out.println("Response received from the server");

            // Closes the streams and the socket
            out.close();
            in.close();
            socket.close();
            return responseJson;

        } catch (JsonProcessingException e) {
            // Captures and displays errors related to JSON processing
            e.printStackTrace();
        } catch (IOException e) {
            // Captures and displays errors related to input/output operations
            System.out.println("calm down, the server is not running yet ");
            //e.printStackTrace();
        }

        return null;
    }

    /**
     * use Base64.getEncoder().encodeToString(signatureBytes); to convert the
     * byte[] signatureBytes to base64, as signatureBase64.
     *
     * @param CPF
     * @param plainText
     * @param signature
     * @return
     */
    public static String createJoinRequestJson(String CPF, String plainText, String signature) {
        // Create the JSON object
        JSONObject jsonRequest = new JSONObject();

        // Add the CPF, plainText, and signature to the JSON
        jsonRequest.put("CPF", CPF);
        jsonRequest.put("text", plainText);
        jsonRequest.put("signature", signature);

        // Return the JSON as a string
        return jsonRequest.toString();
    }

}
