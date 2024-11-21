/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.clientleilao;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author nandones
 */
public class ClientLeilao {
    
    public static Scanner input = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        //testingAES();
        testingSignature();
    }
    
    public static void testingAES() throws Exception{
        String plaintext = "123testandooo";
        SecretKey key = CryptoUtils.generateAESKey();
        String secretKeySTR = CryptoUtils.convertAESKeyToBase64(key);
        System.out.println("secretkey: "+secretKeySTR);
        IvParameterSpec iv = CryptoUtils.generateIvFromAESKey(key);
        String ciphertext = CryptoUtils.encryptWithAES(plaintext, key, iv);
        key = CryptoUtils.convertBase64ToSecretKey(secretKeySTR);
        System.out.println("ciphertext = "+ciphertext);
        System.out.println("texto descriptografado: "+CryptoUtils.decryptWithAES(ciphertext, key, iv));
    }
    
    public static void testingSignature() throws NoSuchAlgorithmException, Exception{
        //emissor
        String message = "with love, russia.";
        KeyPair keypair = CryptoUtils.generateRSAKeyPair();
        PublicKey puk = keypair.getPublic();
        String pukSTR = CryptoUtils.convertPublicKeyToBase64String(puk);
        System.out.println("public key1  : " + pukSTR);
        PrivateKey prk = keypair.getPrivate();
        String prkSTR = CryptoUtils.convertPrivateKeyToBase64String(prk);
        System.out.println("private key1 : " + prkSTR);
        CryptoUtils.hashMessage(message);
        byte[] signatureBytes = CryptoUtils.signMessage(message, prk);
        //receptor
        PublicKey puk2 = CryptoUtils.convertBase64StringToPublicKey(pukSTR);
        PrivateKey prk2 = CryptoUtils.convertBase64StringToPrivateKey(prkSTR);
        pukSTR = CryptoUtils.convertPublicKeyToBase64String(puk2);
        System.out.println("public key2  : " + pukSTR);
        prkSTR = CryptoUtils.convertPrivateKeyToBase64String(prk2);
        System.out.println("private key2 : " + prkSTR);
        System.out.println(CryptoUtils.verifySignature(message, signatureBytes, puk2));
        System.out.println(prk.equals(prk2));
        System.out.println(puk.equals(puk2)); 
        // a new plus test
        System.out.println("insira a public key: ");
        String puk3STR = input.nextLine();
        System.out.println(pukSTR);
        PublicKey puk3 = CryptoUtils.convertBase64StringToPublicKey(puk3STR);
        System.out.println(puk.equals(puk3));
        
    }
}
