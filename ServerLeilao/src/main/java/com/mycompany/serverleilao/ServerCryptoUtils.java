package com.mycompany.serverleilao;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author nandones A class whose purpose is to group together all
 * cryptography-related methods
 */
public class ServerCryptoUtils {
    
    //String signatureBase64 = Base64.getEncoder().encodeToString(signature);
    //byte[] signatureByte = Base64.getDecoder().decode(signatureBase64);
    //we ll need these later.    

    /*
            __   ____  ____ 
           / _\ (  __)/ ___)
          /    \ ) _) \___ \      //font:
          \_/\_/(____)(____/      //https://patorjk.com/software/taag/#p=display&v=3&f=Graceful 
     */
    /**
     * Method to generate a 128-bit AES key
     *
     * @return (SecretKey): The reconstructed SecretKey object for AES
     * encryption and decryption.
     * @throws Exception
     */
    public static SecretKey generateAESKey(){
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // Makes a instance of KeyGenerator to the AES algorithm
            keyGen.init(128); // init the KeyGenerator with the key size as 128 bits
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * This method takes an AES key encoded as a Base64 string and converts it
     * into a usable SecretKey object. It's useful for reconstructing a shared
     * AES key, which may have been transmitted or stored in a Base64 format.
     *
     * @param encodedKey (String): The AES key encoded as a Base64 string.
     * @return (SecretKey): The reconstructed SecretKey object for AES
     * encryption and decryption.
     */
    public static SecretKey convertBase64ToSecretKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey); // Decodes a Base64 String to bytes
        return new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * This method converts an AES SecretKey object into a Base64-encoded string
     * representation. It is useful for securely transmitting or storing the key
     * in text format.
     *
     * @param key The secret key for AES encryption and decryption.
     * @return (String): A Base64-encoded string representation of the provided
     * AES key.
     */
    public static String convertAESKeyToBase64(SecretKey key) {
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        return encodedKey;
    }

    /**
     * This method generates a 16-byte initialization vector (IV) for AES
     * encryption by hashing a given AES SecretKey with SHA-256 and truncating
     * the resulting hash to 16 bytes. It ensures a consistent IV derived from
     * the key, suitable for testing or specific encryption scenarios.
     *
     * @param key The secret key for AES encryption and decryption.
     * @return (IvParameterSpec): A 16-byte IV encapsulated in an
     * IvParameterSpec object.
     * @throws NoSuchAlgorithmException
     */
    public static IvParameterSpec generateIvFromAESKey(SecretKey key){
        try {
            byte[] keyBytes = key.getEncoded(); // Gets the key bytes
            MessageDigest md = MessageDigest.getInstance("SHA-256"); // Uses SHA-256 to ensure 32 bytes of output
            byte[] iv = md.digest(keyBytes); // Generates a hash of the key
            
            byte[] iv16 = new byte[16]; // Creates a 16-byte array for the IV
            System.arraycopy(iv, 0, iv16, 0, 16); // Copies the first 16 bytes of the hash into the IV
            
            return new IvParameterSpec(iv16); // Returns the IV as an IvParameterSpec object
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * This method encrypts a plaintext string using AES encryption with a
     * specified key and initialization vector (IV). It uses CBC (Cipher Block
     * Chaining) mode with PKCS5 padding for secure encryption.
     *
     * @param plainText the (string) to be encrypted
     * @param key (SecretKey) The secret key for AES encryption and decryption.
     * @param iv (IvParameterSpec) the initialization vetor
     * @return (String): The encrypted message encoded in Base64 format.
     * @throws Exception
     */
    public static String encryptWithAES(String plainText, SecretKey key, IvParameterSpec iv){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Creates a Cipher instance using AES/CBC/PKCS5Padding mode
            cipher.init(Cipher.ENCRYPT_MODE, key, iv); // Initializes the Cipher for encryption mode with the key and IV
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes()); // Encrypts the plaintext into bytes and stores in encryptedBytes
            return Base64.getEncoder().encodeToString(encryptedBytes); // Encodes the encrypted bytes in Base64 and returns as a string
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * This method decrypts an encrypted Base64-encoded string using AES
     * decryption with a provided key and initialization vector (IV). It assumes
     * the data was encrypted using AES in CBC mode with PKCS5 padding.
     *
     * @param encryptedText (String): The Base64-encoded ciphertext to decrypt.
     * @param key (SecretKey) The secret key for AES encryption and decryption.
     * @param iv (IvParameterSpec) the initialization vetor
     * @return (String): The decrypted plaintext message.
     * @throws Exception
     */
    public static String decryptWithAES(String encryptedText, SecretKey key, IvParameterSpec iv){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Creates a Cipher instance using AES/CBC/PKCS5Padding mode
            cipher.init(Cipher.DECRYPT_MODE, key, iv); // Initializes the Cipher for decryption mode with the key and IV
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText)); // Decodes the Base64 text and decrypts it
            return new String(decryptedBytes); // Converts the decrypted bytes into a string and returns it
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /*
            ____  ____   __  
           (  _ \/ ___) / _\ 
            )   /\___ \/    \
           (__\_)(____/\_/\_/
     */
    /**
     * Generates an RSA key pair (public and private keys).
     *
     * @return A KeyPair object containing the public and private RSA keys.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available in
     * the environment.
     *
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); // Initializes the RSA key pair generator
        keyGen.initialize(2048); // Sets the key size to 2048 bits (secure);
        return keyGen.generateKeyPair(); // Generates and returns the key pair
    }

    /**
     * Encrypts a plaintext message using the RSA public key.
     *
     * @param plainText The plaintext message to be encrypted.
     * @param publicKey The RSA public key used to encrypt the message.
     * @return A Base64 encoded string representing the encrypted message.
     * @throws Exception If an error occurs during encryption.
     *
     * This method uses the RSA encryption algorithm to encrypt the provided
     * plaintext message. The result is returned as a Base64 encoded string to
     * ensure the encrypted data can be safely transmitted or stored.
     */
    public static String encryptWithRSA(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA"); // Initializes the Cipher with the RSA algorithm
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); // Sets the Cipher for encryption mode using the public key
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes()); // Encrypts the data and stores it in encryptedBytes
        return Base64.getEncoder().encodeToString(encryptedBytes); // Encodes the encrypted data in Base64 and returns as a string
    }

    /**
     * Decrypts a ciphertext message using the RSA private key.
     *
     * @param cipherText The Base64 encoded encrypted message to be decrypted.
     * @param privateKey The RSA private key used to decrypt the message.
     * @return The decrypted plaintext message as a string.
     * @throws Exception If an error occurs during decryption.
     *
     * This method uses the RSA algorithm to decrypt the provided ciphertext
     * message, which is expected to be Base64 encoded. The decrypted message is
     * returned as a string.
     */
    public static String decryptWithRSA(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(cipherText); // Decodes the Base64 string to bytes
        Cipher cipher = Cipher.getInstance("RSA"); // Initializes the Cipher with the RSA algorithm
        cipher.init(Cipher.DECRYPT_MODE, privateKey); // Sets the Cipher for decryption mode using the private key
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes); // Decrypts the data and stores it in decryptedBytes
        return new String(decryptedBytes); // Converts the decrypted bytes to a string and returns it
    }

    /**
     * Signs a message by first hashing it using SHA-256 and then signing the
     * hash with the provided private key. This creates a digital signature that
     * can be used for message verification.
     *
     * @param message The message to be signed.
     * @param privateKey The private RSA key used to sign the message.
     * @return A byte array containing the digital signature of the message from
     * hashing to SHA256.
     * @throws Exception If there is an error during the signing process.
     */
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        // Step 1: Hash the message using SHA-256
        byte[] messageHash = hashMessage(message);

        // Step 2: Initialize the signature object
        Signature signature = Signature.getInstance("SHA256withRSA"); // RSA with SHA-256

        // Step 3: Sign the message hash with the private key
        signature.initSign(privateKey);
        signature.update(messageHash); // Update the signature with the message hash
        return signature.sign(); // Returns the signed message (digital signature)
    }

    /**
     * Verifies a digital signature using the provided RSA public key. The
     * method checks if the signature is valid by comparing it to the hash
     * SHA256 of the received message.
     *
     * @param message The original message to be verified.
     * @param signatureBytes The digital signature to be verified.
     * @param publicKey The RSA public key used to verify the signature.
     * @return {@code true} if the signature is valid, {@code false} otherwise.
     * @throws Exception If there is an error during the signature verification
     * process.
     */
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        // Step 1: Hash the received message (same process as during signing)
        byte[] messageHash = hashMessage(message);

        // Step 2: Initialize the signature object for verification
        Signature signature = Signature.getInstance("SHA256withRSA"); // RSA with SHA-256

        // Step 3: Verify the signature using the public key
        signature.initVerify(publicKey);
        signature.update(messageHash); // Update with the hash of the message
        return signature.verify(signatureBytes); // Returns true if the signature is valid, false otherwise
    }

    /**
     * Converts a PublicKey object to a Base64-encoded string representation.
     *
     * @param publicKey The PublicKey object to be converted.
     * @return A Base64-encoded string representation of the public key.
     */
    public static String convertPublicKeyToBase64String(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded(); // Gets the encoded form of the public key
        return Base64.getEncoder().encodeToString(publicKeyBytes); // Encodes the byte array to a Base64 string and returns it
    }

    /**
     * Converts a PrivateKey object to a Base64-encoded string representation.
     *
     * @param privateKey The PrivateKey object to be converted.
     * @return A Base64-encoded string representation of the private key.
     */
    public static String convertPrivateKeyToBase64String(PrivateKey privateKey) {
        byte[] privateKeyBytes = privateKey.getEncoded(); // Gets the encoded form of the private key
        return Base64.getEncoder().encodeToString(privateKeyBytes); // Encodes the byte array to a Base64 string and returns it
    }

    /**
     * Reconstructs a PublicKey object from a Base64-encoded string.
     *
     * @param publicKeyString The Base64-encoded string representing the public
     * key.
     * @return The reconstructed PublicKey object.
     * @throws Exception If an error occurs during the reconstruction process,
     * such as invalid input or unsupported algorithm.
     */
    public static PublicKey convertBase64StringToPublicKey (String publicKeyString) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString); // Decodes the Base64 string to a byte array
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes); // Wraps the byte array in an X509EncodedKeySpec
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Gets a KeyFactory instance for RSA
            return keyFactory.generatePublic(keySpec); // Generates and returns the PublicKey object
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * Reconstructs a Private object from a Base64-encoded string.
     *
     * @param privateKeyString The Base64-encoded string representing the private
     * key.
     * @return The reconstructed PrivateKey object.
     * @throws Exception If an error occurs during the reconstruction process,
     * such as invalid input or unsupported algorithm.
     */
    public static PrivateKey convertBase64StringToPrivateKey (String privateKeyString){
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString); // Decodes the Base64 string to a byte array
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes); // Wraps the byte array in an X509EncodedKeySpec
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Gets a KeyFactory instance for RSA
            return keyFactory.generatePrivate(keySpec); // Generates and returns the PrivateKey object
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(ServerCryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }


    /*
            _  _   __   ____  _  _ 
           / )( \ / _\ / ___)/ )( \
           ) __ (/    \\___ \) __ (
           \_)(_/\_/\_/(____/\_)(_/
     */
    /**
     * Hashes the input message using the SHA-256 algorithm.
     *
     * @param message The message to be hashed.
     * @return A byte array containing the SHA-256 hash of the message.
     * @throws NoSuchAlgorithmException If the SHA-256 algorithm is not
     * available.
     */
    public static byte[] hashMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Initialize SHA-256 algorithm
        return digest.digest(message.getBytes()); // Returns the hash of the message
    }

}
