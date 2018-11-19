/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package asymetricencode;

import static asymetricencode.AsymetricEncodeTest.ALGORITHM;
import static asymetricencode.AsymetricEncodeTest.PRIVATE_KEY_FILE_NAME;
import static asymetricencode.AsymetricEncodeTest.PUBLIC_KEY_FILE_NAME;
import custom.Functions;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.bouncycastle.jcajce.provider.digest.SHA3;

/**
 *
 * @author colt
 */
public class Cryptor {
    //used for hashing function
    //can be transmitted for new session
    private static long MAGIC_NUMBER = 123321;
    
    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
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
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);
 
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new String(dectyptedText);
    }
    
    public static void generateSessionKeys(String privatefilename, String publicfilename) {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024, new SecureRandom());
            final KeyPair key = keyGen.generateKeyPair();
 
            File privateKeyFile = new File(privatefilename);
            File publicKeyFile = new File(publicfilename);
 
            if (privateKeyFile.getParentFile() != null) {
                privateKeyFile.getParentFile().mkdirs();
            }
            privateKeyFile.createNewFile();
 
            if (publicKeyFile.getParentFile() != null) {
                publicKeyFile.getParentFile().mkdirs();
            }
            publicKeyFile.createNewFile();
 
            BufferedWriter pubOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(publicKeyFile)));
            pubOut.write(Functions.byte2Hex(key.getPublic().getEncoded()));
            pubOut.flush();
            pubOut.close();
 
            BufferedWriter privOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(privateKeyFile)));
            privOut.write(Functions.byte2Hex(key.getPrivate().getEncoded()));
            privOut.flush();
            privOut.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
 
    }    
    
    public static PublicKey keyRestorePublicFromPrivateFile(String privatefilename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { 
        PrivateKey pk = Cryptor.KeyPrivateRestoreFromFile(privatefilename);            
        RSAPrivateCrtKey pkcrt = (RSAPrivateCrtKey)pk;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(pkcrt.getModulus(), pkcrt.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(publicKeySpec);
    }   
    
    public static PublicKey keyRestorePublicFromPrivate(PrivateKey pk) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { 
        RSAPrivateCrtKey pkcrt = (RSAPrivateCrtKey)pk;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(pkcrt.getModulus(), pkcrt.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(publicKeySpec);
    }   
 
    public static byte[] fileToKey(String file) throws IOException {
        BufferedReader pubIn = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        StringBuilder sb = new StringBuilder();
        String tmp;
        do {
            tmp = pubIn.readLine();
            if (tmp != null) sb.append(tmp);
        } while (tmp != null);
        return Functions.hex2Byte(sb.toString());
    }
 
    public static PublicKey KeyPublicRestoreFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(fileToKey(filename));
        return keyFactory.generatePublic(publicKeySpec);
    }
 
    public static PrivateKey KeyPrivateRestoreFromFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(fileToKey(filename));
        return keyFactory.generatePrivate(privateKeySpec);
    }
    
    public static byte[] getSHA3(byte[] input){
        SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
            md.update(input);
            for(long i=0; i < MAGIC_NUMBER; i++){
                md.update(md.digest());
            }
        return md.digest();
    }
    
    public static byte[] getSHA3(String input) throws UnsupportedEncodingException{
        SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
            md.update(input.getBytes("UTF-8"));
            for(long i=0; i < MAGIC_NUMBER; i++){
                md.update(md.digest());
            }
        return md.digest();
    }
}
