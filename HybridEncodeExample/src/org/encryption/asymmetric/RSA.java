/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.asymmetric;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

/**
 * Asymmetric key cryptography (also known as public key cryptography) refers to 
 * a system that requires two separate keys, one of which is secret and one of which is public. 
 * Although different, the two parts of the key pair are mathematically linked. 
 * One key encrypts the plain text, and the other decrypts the cipher text. 
 * Neither key can perform both functions. The public key, or the key used to 
 * encrypt information can be freely distributed.
 * 
 * 
 * 
 * @author colt
 */
public class RSA {
    
    /*
     * Every implementation of the Java platform is required to support 
     * the following standard KeyPairGenerator algorithms and keysizes in parentheses: 
    
    *   DiffieHellman (1024)
    *   DSA (1024)
    *   RSA (1024, 2048)
    */
    private static final String KEYPAIRGENERATOR_ALGORITHM = "RSA";
    private static final int KEYPAIRGENERATOR_ALGORITHM_KEYSIZE = 2048;    
    
    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance(KEYPAIRGENERATOR_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }
    
    public static String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance(KEYPAIRGENERATOR_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);
 
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new String(dectyptedText);
    }
    
   /**
    * Generate key which contains a pair of private and public key 
    * using KEYPAIRGENERATOR_ALGORITHM_KEYSIZE bytes. 
    */
    public static KeyPair keyPairGenerate() {
        KeyPairGenerator kpgen;
        try {
            kpgen = KeyPairGenerator.getInstance(KEYPAIRGENERATOR_ALGORITHM);
            
            //Initializes the key pair generator for a certain keysize with 
            //the given source of randomness (and a default parameter set).
            kpgen.initialize(KEYPAIRGENERATOR_ALGORITHM_KEYSIZE, new SecureRandom());
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException();
        }
        //what for!?
        //kpgen.initialize(size);
        
        return kpgen.generateKeyPair();
    }   
    
    /**
     * Encode key to byte array
     * RSA private keys are encoded in PKCS#8 format, and public keys are encoded in X.509 format.
     * @param rsaPublicKey
     * @return 
     */
    public static byte[] encodeKey(final RSAPublicKey rsaPublicKey) {
        return rsaPublicKey.getEncoded();
    }
    
    /**
     * Decode byte array to key
     * @param x509EncodedPUblicKey
     * @return
     * @throws InvalidKeySpecException 
     */
    public static RSAPublicKey decodePublicKey(final byte[] x509EncodedPUblicKey) throws InvalidKeySpecException {
        try {
            final KeyFactory rsaPublicKeyFactory = KeyFactory.getInstance(KEYPAIRGENERATOR_ALGORITHM);
            final PublicKey pubKey = rsaPublicKeyFactory.generatePublic(new X509EncodedKeySpec(x509EncodedPUblicKey));
            return (RSAPublicKey) pubKey;
        } catch (final InvalidKeySpecException e) {
            throw e;
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    
    public static RSAPrivateKey decodePrivateKey(final byte[] PKCS8EncodedPrivateKey) throws InvalidKeySpecException {
        try {
            final KeyFactory rsaPublicKeyFactory = KeyFactory.getInstance(KEYPAIRGENERATOR_ALGORITHM);
            final PublicKey pubKey = rsaPublicKeyFactory.generatePublic(new PKCS8EncodedKeySpec(PKCS8EncodedPrivateKey));
            return (RSAPrivateKey) pubKey;
        } catch (final InvalidKeySpecException e) {
            throw e;
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
