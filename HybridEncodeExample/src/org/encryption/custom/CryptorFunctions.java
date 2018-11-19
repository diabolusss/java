/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.custom;

import org.encryption.asymmetric.RSA;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.mindrot.jbcrypt.BCrypt;

/**
 *
 * @author colt
 */
public class CryptorFunctions {
    //A MAC mechanism that is based on cryptographic hash functions is referred to as HMAC. 
    //HMAC can be used with any cryptographic hash function, e.g., MD5 or SHA-1, 
    //in combination with a secret shared key. HMAC is specified in RFC 2104. 
    //Every implementation of the Java platform is required to support the following standard Mac algorithms: 
    //  HmacMD5
    //  HmacSHA1
    //  HmacSHA256 
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int HMAC_KEY_LENGTH_BITS = 256;
    
    private static final int HASH_ALGORITHM_ITERATIONS = 0;
    
    //private static final int HASH_ALGORITHM_SHA3 = 0;
    //private static final int HASH_ALGORITHM_SRND = 1;
    // Define the BCrypt workload to use when generating password hashes. 10-31 is a valid value.
    // A workload of 12 is a very reasonable safe default as of 2013.
    //private static final int HASH_ALGORITHM_BCRYPT = 16;
    
    //"SHA1PRNG" uses a hash function and a counter, together with a seed. 
    //  The algorithm is relatively simple, but it hasn't been described well. 
    //  It is generally thought of to be secure. As it only seeds from one of the system 
    //  generators during startup and therefore requires fewer calls to the kernel 
    //  it is likely to be less resource intensive -
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    
    //private static int SALT_HASH_ALGORITHM = 
            //HASH_ALGORITHM_SHA3
            //HASH_ALGORITHM_BCRYPT
            //HASH_ALGORITHM_SRND            
            //;
    
    //public static final int SALT_HASH_SIZE = 20;
    
    public static byte[] getRandomBytes(int length) throws GeneralSecurityException {
        //Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] b = new byte[length];
        random.nextBytes(b);
        return b;
    }
    
    /*public static byte[] generateSalt() throws UnsupportedEncodingException, GeneralSecurityException{
        byte[] salt = new byte[SALT_HASH_SIZE];
        
        switch(SALT_HASH_ALGORITHM){
            case HASH_ALGORITHM_SHA3:
                break;
                
            case HASH_ALGORITHM_BCRYPT:
                break;
                
            case HASH_ALGORITHM_SRND:
                salt = getRandomBytes(SALT_HASH_SIZE);
                break;
        }
        //String salt_ = 
                //Functions.byte2Hex(BCrypt.gensalt(HASH_ALGORITHM_BCRYPT).substring(7).getBytes("UTF-8"));
        //        Functions.byte2Hex(salt);
        //        ;
        //System.out.println("Generated salt["+salt_.length()+"]: "+salt_+"; Actual:"+Functions.byte2Hex(salt));
        
        return salt;
    }*/
    
    /**
     * Restore public key from given private key
     * @param pk
     * @param algorithm
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static PublicKey restorePublicKey(PrivateKey pk, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { 
        RSAPrivateCrtKey pkcrt = (RSAPrivateCrtKey)pk;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(pkcrt.getModulus(), pkcrt.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(publicKeySpec);
    }
    
    /**
     * Restore public key from private key. which is stored into file
     * @param privatefilename
     * @param algorithm
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static PublicKey restorePublicKey(String privatefilename, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { 
        PrivateKey pk = RSA.decodePrivateKey(Functions.file2Byte(privatefilename));       
        
        return restorePublicKey(pk, algorithm);
    } 
    
    /**
     * Restore public key from file
     * @param publicfilename
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static PublicKey restorePublicKey(String publicfilename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return RSA.decodePublicKey(Functions.file2Byte(publicfilename));
    }
    
    /**
     * Generate the mac based on HMAC_ALGORITHM for later integrity checking
     * 
     * A MAC provides a way to check the integrity of information transmitted over 
     *  or stored in an unreliable medium, based on a secret key. Typically, message authentication 
     *  codes are used between two parties that share a secret key in order 
     *  to validate information transmitted between these parties. 
     * 
     * A MAC mechanism that is based on cryptographic hash functions is referred to as HMAC. 
     *  HMAC can be used with any cryptographic hash function, e.g., MD5 or SHA-1, 
     *  in combination with a secret shared key. HMAC is specified in RFC 2104. 
     * 
     * @param integrityKey The key used for hmac
     * @param byteCipherText the cipher text
     * @return A byte array of the HMAC for the given key & ciphertext
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] generateMAC(byte[] byteCipherText, SecretKey integrityKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac HMAC = Mac.getInstance(HMAC_ALGORITHM);
        HMAC.init(integrityKey);
        return HMAC.doFinal(byteCipherText);
    }
    
    public static byte[] getSHA3(byte[] input){
        SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
            md.update(input);
            for(long i=0; i < HASH_ALGORITHM_ITERATIONS; i++){
                md.update(md.digest());
            }
        return md.digest();
    }
    
    public static byte[] getSHA3(String input) throws UnsupportedEncodingException{
        return getSHA3(input.getBytes("UTF-8"));
    }
}
