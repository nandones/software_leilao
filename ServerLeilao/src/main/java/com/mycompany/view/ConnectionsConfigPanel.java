/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
package com.mycompany.view;

import com.mycompany.serverleilao.ServerCommunication;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingUtilities;

/**
 *
 * @author nandones
 */
public class ConnectionsConfigPanel extends javax.swing.JPanel {

    /**
     * Creates new form Panel1
     */
    public ConnectionsConfigPanel() {
        initComponents();
        initLabelAdressServer();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jButton1 = new javax.swing.JButton();
        labelTitle = new javax.swing.JLabel();
        jButton2 = new javax.swing.JButton();
        labelHandshakeServerAddress = new javax.swing.JLabel();
        labelHanshekeServerPort = new javax.swing.JLabel();
        labelMulticastAdress = new javax.swing.JLabel();
        labelMulticastPort = new javax.swing.JLabel();
        labelDynamicServerAddress = new javax.swing.JLabel();
        textFieldServerPort = new javax.swing.JTextField();
        textFieldMulticastAdress = new javax.swing.JTextField();
        textFieldMulticastPort = new javax.swing.JTextField();
        labelConfigRules = new javax.swing.JLabel();

        jButton1.setText("switch panel");

        labelTitle.setText("ABRIR SALA LEILÃO:");

        jButton2.setText("turn server on");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        labelHandshakeServerAddress.setText("HANSHAKE SERVER ADRESS:");

        labelHanshekeServerPort.setText("HANDSHAKE SERVER PORT:");

        labelMulticastAdress.setText("MULTICAST ADRESS:");

        labelMulticastPort.setText("MULTICAST  PORT:");

        labelDynamicServerAddress.setText("0.0.0.0");

        textFieldServerPort.setText("12345");
        textFieldServerPort.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                textFieldServerPortActionPerformed(evt);
            }
        });

        textFieldMulticastAdress.setText("230.0.0.1");
        textFieldMulticastAdress.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                textFieldMulticastAdressActionPerformed(evt);
            }
        });

        textFieldMulticastPort.setText("50000");
        textFieldMulticastPort.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                textFieldMulticastPortActionPerformed(evt);
            }
        });

        labelConfigRules.setText("<html>The multicast address must be within the reserved range: <br>224.0.0.0 through 239.255.255.255.<br>Use ports in the range 49152–65535 (ephemeral ports).</html>");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(147, 147, 147)
                                .addComponent(labelTitle))
                            .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(labelHandshakeServerAddress)
                                .addGap(18, 18, 18)
                                .addComponent(labelDynamicServerAddress, javax.swing.GroupLayout.PREFERRED_SIZE, 105, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGap(0, 286, Short.MAX_VALUE)
                                .addComponent(jButton2))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(labelHanshekeServerPort)
                                    .addComponent(labelMulticastAdress)
                                    .addComponent(labelMulticastPort))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(textFieldMulticastPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(textFieldMulticastAdress, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(textFieldServerPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(labelConfigRules))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(labelTitle)
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelHandshakeServerAddress)
                    .addComponent(labelDynamicServerAddress))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(labelHanshekeServerPort)
                    .addComponent(textFieldServerPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(labelMulticastAdress)
                    .addComponent(textFieldMulticastAdress, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(labelMulticastPort)
                    .addComponent(textFieldMulticastPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(labelConfigRules, javax.swing.GroupLayout.DEFAULT_SIZE, 93, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButton2)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void initLabelAdressServer() {
        try {
            labelDynamicServerAddress.setText(InetAddress.getLocalHost().getHostAddress());
        } catch (UnknownHostException ex) {
            Logger.getLogger(ConnectionsConfigPanel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        int serverSocketInt = Integer.parseInt(textFieldServerPort.getText());

        // Configuring the server socket in a separate thread
        Thread serverThread = new Thread(() -> {
            try {
                ServerCommunication.serverSocket = new ServerSocket(serverSocketInt);
                while(true){
                ServerCommunication.receiveAndProcessJoinRequest(ServerCommunication.serverSocket);
                }
            } catch (IOException ex) {
                Logger.getLogger(ServerCommunication.class.getName()).log(Level.SEVERE, null, ex);
            }
        });

        // Switching to the next panel in another thread
        Thread panelSwitchThread = new Thread(() -> {
            MainFrame mainFrame = (MainFrame) SwingUtilities.getWindowAncestor(this);
            mainFrame.switchPanel(new Panel2());
        });

        // Starting both threads
        serverThread.start();
        panelSwitchThread.start();

    }//GEN-LAST:event_jButton2ActionPerformed

    private void textFieldServerPortActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_textFieldServerPortActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_textFieldServerPortActionPerformed

    private void textFieldMulticastAdressActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_textFieldMulticastAdressActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_textFieldMulticastAdressActionPerformed

    private void textFieldMulticastPortActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_textFieldMulticastPortActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_textFieldMulticastPortActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel labelConfigRules;
    private javax.swing.JLabel labelDynamicServerAddress;
    private javax.swing.JLabel labelHandshakeServerAddress;
    private javax.swing.JLabel labelHanshekeServerPort;
    private javax.swing.JLabel labelMulticastAdress;
    private javax.swing.JLabel labelMulticastPort;
    private javax.swing.JLabel labelTitle;
    private javax.swing.JTextField textFieldMulticastAdress;
    private javax.swing.JTextField textFieldMulticastPort;
    private javax.swing.JTextField textFieldServerPort;
    // End of variables declaration//GEN-END:variables
}