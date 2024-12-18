/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
package com.mycompany.view;

import com.mycompany.clientleilao.ClientAuction;
import com.mycompany.clientleilao.ClientCryptoUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.UnknownHostException;
import java.rmi.server.ServerCloneException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import org.json.JSONObject;

/**
 *
 * @author nandones
 */
public class BidPanel extends javax.swing.JPanel {

    /**
     * Creates new form Panel2
     */
    public BidPanel() {
        initComponents();
        textAreaBids.setText("[connected]\n");
        textAreaBids.setEditable(false);
        ClientAuction.multicastSocket = createMulticastRoom();
        startReceivingMessages();
        //startSendingMessages();
        joinBiding();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        buttonMakeABid = new javax.swing.JButton();
        labelName = new javax.swing.JLabel();
        labelDescription = new javax.swing.JLabel();
        labelCurrentPrice = new javax.swing.JLabel();
        labelBidIncrement = new javax.swing.JLabel();
        labelChronometer = new javax.swing.JLabel();
        labelItem = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        textAreaBids = new javax.swing.JTextArea();
        labelDynamicName = new javax.swing.JLabel();
        labelDynamicDescription = new javax.swing.JLabel();
        labelDynamicCurrentPrice = new javax.swing.JLabel();
        labelDynamicBidIncrement = new javax.swing.JLabel();
        labelDynamicChronometer = new javax.swing.JLabel();

        jLabel1.setText("BIDDING:");

        buttonMakeABid.setText("make a bid for");
        buttonMakeABid.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonMakeABidActionPerformed(evt);
            }
        });

        labelName.setText("name:");

        labelDescription.setText("description:");

        labelCurrentPrice.setText("current price:");

        labelBidIncrement.setText("bid increment:");

        labelChronometer.setText("chronometer:");

        labelItem.setText("Item:");

        textAreaBids.setColumns(20);
        textAreaBids.setRows(5);
        jScrollPane1.setViewportView(textAreaBids);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(165, 165, 165)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(labelName)
                                .addGap(18, 18, 18)
                                .addComponent(labelDynamicName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(labelDescription)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(labelDynamicDescription, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 388, Short.MAX_VALUE)
                            .addComponent(buttonMakeABid, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(labelCurrentPrice)
                                .addGap(18, 18, 18)
                                .addComponent(labelDynamicCurrentPrice, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(labelChronometer)
                                .addGap(18, 18, 18)
                                .addComponent(labelDynamicChronometer, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(labelBidIncrement)
                                .addGap(18, 18, 18)
                                .addComponent(labelDynamicBidIncrement, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
                .addContainerGap())
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(labelItem)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(7, 7, 7)
                .addComponent(labelItem)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelName)
                    .addComponent(labelDynamicName))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelDescription)
                    .addComponent(labelDynamicDescription))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelCurrentPrice)
                    .addComponent(labelDynamicCurrentPrice))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelBidIncrement)
                    .addComponent(labelDynamicBidIncrement))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelChronometer)
                    .addComponent(labelDynamicChronometer))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 98, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(buttonMakeABid)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    public static void joinBiding(){
             try {
                JSONObject json = new JSONObject();
                json.put("sender", ClientAuction.USER);
                json.put("CPF", ClientAuction.CPF);
                json.put("action", "getDetailsAboutItem");
                InetAddress group = InetAddress.getByName(ClientAuction.multicastAddress);
                String message = json.toString();
                String encodedMessage = ClientCryptoUtils.encryptWithAES(message, ClientAuction.secretKey, ClientAuction.iv);
                
                
                byte[] buffer = encodedMessage.getBytes();
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, group, ClientAuction.multicastPort);
                ClientAuction.multicastSocket.send(packet); // Sends the message
                System.out.println("joinBiding: " + message);
                
            } catch (IOException e) {
                System.err.println("Error in sending messages: " + e.getMessage());
            }
        
    }
    
    public static void makeABid(){
        try {
                JSONObject json = new JSONObject();
                json.put("sender", ClientAuction.USER);
                json.put("CPF", ClientAuction.CPF);
                json.put("action", "makeABid");
                json.put("value", ClientAuction.nextbid);
                InetAddress group = InetAddress.getByName(ClientAuction.multicastAddress);
                String message = json.toString();
                String encodedMessage = ClientCryptoUtils.encryptWithAES(message, ClientAuction.secretKey, ClientAuction.iv);
                
                
                byte[] buffer = encodedMessage.getBytes();
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, group, ClientAuction.multicastPort);
                ClientAuction.multicastSocket.send(packet); // Sends the message
                System.out.println("joinBiding: " + message);
                
            } catch (IOException e) {
                System.err.println("Error in sending messages: " + e.getMessage());
            }
    }
    

    public static MulticastSocket createMulticastRoom() {
        try {
            InetAddress group = InetAddress.getByName(ClientAuction.multicastAddress);
            MulticastSocket multicastSocket = new MulticastSocket(ClientAuction.multicastPort);
            multicastSocket.joinGroup(group);
            System.out.println("Multicast room created at " + ClientAuction.multicastAddress + ":" + ClientAuction.multicastPort);
            return multicastSocket;
        } catch (UnknownHostException ex) {
            Logger.getLogger(BidPanel.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(BidPanel.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public void startReceivingMessages() {
        Thread receiverThread = new Thread(() -> {
            try {
                byte[] buffer = new byte[1024];

                while (true) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    ClientAuction.multicastSocket.receive(packet); // Waits for a message
                    String receivedEncodedMessage = new String(packet.getData(), 0, packet.getLength());
                    String receivedMessage = ClientCryptoUtils.decryptWithAES(receivedEncodedMessage, ClientAuction.secretKey, ClientAuction.iv);
                    System.out.println("RECEIVEDMESSAGEJSON: "+ receivedMessage);
                    JSONObject jsonRecieved = new JSONObject(receivedMessage);
                    String sender = jsonRecieved.getString("sender");
              
                    if (sender.equalsIgnoreCase("server")) {//just looks for server messages
                        String action = jsonRecieved.getString("action");
                        
                        if ("itemDetails".equalsIgnoreCase(action)) {//if contains details of the item
                            ClientAuction.itemName = jsonRecieved.getString("name");
                            ClientAuction.itemDescription = jsonRecieved.getString("description");
                            ClientAuction.currentPrice = jsonRecieved.getFloat("currentPrice");
                            ClientAuction.bidIncrement = jsonRecieved.getFloat("bidIncrement");
                            ClientAuction.chronometer = jsonRecieved.getInt("chronometer");
                            ClientAuction.nextbid = ClientAuction.currentPrice+ClientAuction.bidIncrement;
                            
                            labelDynamicName.setText(ClientAuction.itemName);
                            labelDynamicDescription.setText(ClientAuction.itemDescription);
                            labelDynamicCurrentPrice.setText(String.valueOf(ClientAuction.currentPrice));
                            labelDynamicBidIncrement.setText(String.valueOf(ClientAuction.bidIncrement));
                            labelDynamicChronometer.setText(String.valueOf(ClientAuction.chronometer));
                            
                            if(ClientAuction.itemName.equalsIgnoreCase("")){//there's no item
                                buttonMakeABid.setText("waiting for a bid");
                                buttonMakeABid.setEnabled(false);
                            }else{//there´s an item
                                buttonMakeABid.setText("make a bid for "+ClientAuction.nextbid);
                                buttonMakeABid.setEnabled(true);
                                if(jsonRecieved.has("CPF")){
                                    String CPF = jsonRecieved.getString("CPF");
                                    textAreaBids.append(("CPF : "+CPF+" is holding the highest bid with "+ClientAuction.currentPrice+"\n"));
                                }
                            }//there´s an item
                        }//if contains details of the item
                        if(action.equalsIgnoreCase("declareWinner")){
                            String winnerCPF = jsonRecieved.getString("CPF");
                            textAreaBids.append("CPF : "+winnerCPF+" have bought "+ClientAuction.itemName+" for "+ClientAuction.currentPrice+" monetary units.\n");
                        }
                        
                        
                    }//just looks for server messages
                    
                }
            } catch (IOException e) {
                System.err.println("Error in receiving messages: " + e.getMessage());
            }
        });
        receiverThread.start();
    }

    /**
     * If the development team (myself) decides to open a chat simultaneously to
     * the auction, but requires further modifications (jsons, textAreas, AES)
     */
    public static void startSendingMessages() {

        Thread senderThread = new Thread(() -> {
            try {
                InetAddress group = InetAddress.getByName(ClientAuction.multicastAddress);
                BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("Type messages to send:");
                String message;
                while ((message = userInput.readLine()) != null) {
                    byte[] buffer = message.getBytes();
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, group, ClientAuction.multicastPort);
                    ClientAuction.multicastSocket.send(packet); // Sends the message
                    System.out.println("Sent: " + message);
                }
            } catch (IOException e) {
                System.err.println("Error in sending messages: " + e.getMessage());
            }
        });
        senderThread.start();
    }


    private void buttonMakeABidActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonMakeABidActionPerformed
        makeABid();
    }//GEN-LAST:event_buttonMakeABidActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonMakeABid;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel labelBidIncrement;
    private javax.swing.JLabel labelChronometer;
    private javax.swing.JLabel labelCurrentPrice;
    private javax.swing.JLabel labelDescription;
    private javax.swing.JLabel labelDynamicBidIncrement;
    private javax.swing.JLabel labelDynamicChronometer;
    private javax.swing.JLabel labelDynamicCurrentPrice;
    private javax.swing.JLabel labelDynamicDescription;
    private javax.swing.JLabel labelDynamicName;
    private javax.swing.JLabel labelItem;
    private javax.swing.JLabel labelName;
    private javax.swing.JTextArea textAreaBids;
    // End of variables declaration//GEN-END:variables
}
