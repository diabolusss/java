/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.symmetric;

import org.encryption.custom.CryptorFunctions;
import org.encryption.custom.Functions;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * GCM is an Authenticated Encryption mode. 
 * It provides you with confidentiality (encryption), integrity, and authentication (MAC) in one go.
 * 
 * Padding: by default, Java uses PKCS#7 padding. That works, but it is often vulnerable 
 *  to padding oracle attacks which are best defeated with a MAC. 
 * 
 *  * GCM embeds already a MAC (called GMAC).
 * 
 * Having said that, one must be aware that GCM security relies on a good random 
 * number generation for creation of the IV.
 * 
 * Because reusing an nonce/key combination destroys the security guarantees of AES-GCM mode, 
 * it can be difficult to use this mode securely when using statically configured keys. 
 * For safety's sake, implementations MUST use an automated key management system, 
 * such as the Internet Key Exchange (IKE) [RFC2409], to ensure that this requirement is met.
 * 
 */
public class AESGCM {
    //Constructs secret keys using the Password-Based Key Derivation Function 
    //function found in PKCS #5 v2.0.
    //PBKDF2 Stands for Password-based-Key-Derivative-Function, a successor of PBKDF1 
    //  and is used to implement a pseudorandom function, such as a cryptographic hash, 
    //  cipher, or HMAC to the input password or passphrase along with a salt value and 
    //  repeats the process many times to produce a derived key, which can then be used 
    //  as a cryptographic key in subsequent operations.
    //HMAC Stands for Keyed-Hash Message Authentication Code (HMAC) is a specific construction 
    //  for calculating a message authentication code (MAC) involving a cryptographic hash function 
    //  in combination with a secret cryptographic key. Any cryptographic hash function,
    //  may be used in the calculation of an HMAC; the resulting MAC algorithm is termed HMAC-MD5 
    //  or HMAC-SHA1 accordingly.
    
    //HMACSHA1 is a type of keyed hash algorithm that is constructed from the SHA1 hash 
    //  function and used as an HMAC, or hash-based message authentication code. The HMAC process 
    //  mixes a secret key with the message data, hashes the result with the hash function, mixes 
    //  that hash value with the secret key again, and then applies the hash function a second 
    //  time. The output hash is 160 bits in length.
    // HMACSHA512 The output hash is 512 bits in length.
    private static final String SECRETKEY_DERIVATION_FUNC = "PBKDF2WithHmacSHA1";
    
    //The parameter keyLength is used to indicate the preference on key length for variable-key-size ciphers.
    //The actual key size depends on each provider's implementation. 
    private static final int SECRETKEY_DERIVATION_SIZE = 128;
    
    public static final int SECRETKEY_DERIVATION_SALT_SIZE_BYTE = 20;
    
    //Iteration count is the number of times that the password is hashed during the derivation 
    //of the symmetric key. The higher number, the more difficult it is to brute force the key. 
    //It is used together with the salt which is used to prevent against attacks using rainbow tables.
    private static final int SECRETKEY_DERIVATION_ITERATIONS = Character.MAX_VALUE*10; //100; 27sec
    
    private static final String SECRETKEY_DERIVATION_ALGORITHM = "AES";
    
    //GCM is Galois/Counter Mode created by McGrew and Viega. It is a NIST approved mode
    //which operates over a Galois field.  
    //GCM implementations are unique in that the mode's throughput can be increased by 
    //using larger precomputation (at the cost of a memory tradeoff).
    public static final String SECRETKEY_CIPHER_WRAP_ALGORITHM = "AES/GCM/NoPadding";
    
    /**
     * Encrypt string with given key
     * @param plaintext
     * @param secretKey
     * @return initVector+encodedString
     * @throws GeneralSecurityException 
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey secretKey)  throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(SECRETKEY_CIPHER_WRAP_ALGORITHM);
        
        //geenrate initialization vector
        //byte[] iv = AESCBCIntegrity.generateIV();
        //In the case of AES, a block is 16 bytes, or 128 bits. 
        byte[] iv = CryptorFunctions.getRandomBytes(aesCipher.getBlockSize());
        
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        
        // * Now we get back the IV that will actually be used. Some Android
        // * versions do funny stuff w/ the IV, so this is to workaround bugs:
        iv = aesCipher.getIV();
        
        //finalize encode
        byte[] encodedText = aesCipher.doFinal(plaintext);
        
        //add init vector ?FOR WHAT?
        byte[] ivCipherConcat = Functions.byteConcat(iv, encodedText);

        return ivCipherConcat;
    }
    
    /**
     * Decrypts encoded data with given key with no integrity check
     * @param encryptedData
     * @param secretKey
     * @return
     * @throws GeneralSecurityException 
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey secretKey)  throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(SECRETKEY_CIPHER_WRAP_ALGORITHM);
        
        int offset = aesCipher.getBlockSize();
        final byte[] iv = Arrays.copyOfRange(encryptedData, 0, offset);
        
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        
        return aesCipher.doFinal(Arrays.copyOfRange(encryptedData, offset, encryptedData.length));
    }
    
    /**
     * A function that generates password-based AES key. It prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @param password The password to derive the keys from.
     * @return The AES  key.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */    
    public static SecretKey generateKey(final byte[] salt, final char[] password) {
        try {
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRETKEY_DERIVATION_FUNC);
            
            //A user-chosen password that can be used with password-based encryption (PBE).
            final KeySpec spec = new PBEKeySpec(password, salt, SECRETKEY_DERIVATION_ITERATIONS, SECRETKEY_DERIVATION_SIZE);
            
            //get random secret key from given specs
            final SecretKey rawDerivedKey = factory.generateSecret(spec);
            
            //Generate the SECRETKEY_DERIVATION_ALGORITHM key
            final SecretKey secret = new SecretKeySpec(rawDerivedKey.getEncoded(), SECRETKEY_DERIVATION_ALGORITHM);
            //SecretKey confidentialityKey = new SecretKeySpec(confidentialityKeyBytes, SECRETKEY_DERIVATION_ALGORITHM);

            return secret;

        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }        
    }
    
    public static SecretKey generateKey(final byte[] salt, final String password) {
        return generateKey(salt, password.toCharArray());
    }
    //The wrap modes are provided for the purpose of allowing providers to provide 
    //  facilities for "key wrapping", or the encryption of the encoded form of the keys. 
    //  There are two reasons for doing this. The first is simple convenience 
    //  ”you do not have to extract the key's data; to wrap it, you just call 
    //  Cipher.wrap()  and the key is extracted for you and returned as an encrypted byte array. 
    //  The second reason is that some providers will store the actual key material 
    //  on hardware devices where it is safe from prying eyes; the wrapping mechanism 
    //  provides a means of getting the key material out of the device without exposing the 
    //  raw material unencrypted. 
    
    /*
     * The last thing to note in the example, modified or otherwise , is that 
     *  the key doing the wrapping is a larger bit size than the key being wrapped. 
     *  If it were the other way around, it would be easier to guess the wrapping key 
     *  than guess the key being wrapped. Put another way, if you were to wrap a 256-bit AES key 
     *  using a 40-bit ARC4 key, you only have 40 bits of security, not 256, 
     *  protecting the data encrypted with the AES key.  
     * 
     * Important  
     *  Keys used for wrapping should always be at least as secure, 
     *  if not more so, than the key being protected.
     */
    public static byte[] wrapPrivateKeyRSA(final RSAPrivateKey rsaPrivateKey,final SecretKey aesKey) {
        try {
             //Padding messages is a way to make it harder to do traffic analysis. 
            //Normally, a number of random bits are appended to the end of 
            //the message with an indication at the end how much this random data is. 
            final Cipher c = Cipher.getInstance(SECRETKEY_CIPHER_WRAP_ALGORITHM);

            //In the case of AES, a block is 16 bytes, or 128 bits. 
            final byte[] iv = CryptorFunctions.getRandomBytes(c.getBlockSize());
            
            c.init(Cipher.WRAP_MODE, aesKey, new IvParameterSpec(iv));
            final byte[] wrappedKey = c.wrap(rsaPrivateKey);
            
            return Functions.byteConcat(iv, wrappedKey);
            
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    
    public static RSAPrivateKey unwrapPrivateKeyRSA(final byte[] encryptedRSAPrivateKey,final SecretKey aesKey) throws InvalidKeyException {
        try {
            final Cipher c = Cipher.getInstance(SECRETKEY_CIPHER_WRAP_ALGORITHM);

            int offset = c.getBlockSize();
            // Copies the specified range of the specified array into a new array.
            final byte[] iv = Arrays.copyOfRange(encryptedRSAPrivateKey, 0, offset);

            c.init(Cipher.UNWRAP_MODE, aesKey, new IvParameterSpec(iv));
            final Key key = c.unwrap(Arrays.copyOfRange(encryptedRSAPrivateKey, offset, encryptedRSAPrivateKey.length), "RSA", Cipher.PRIVATE_KEY);
            return (RSAPrivateKey) key;
        } catch (final InvalidKeyException e) {
            throw e;
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    
    /**
     * Generates a random salt.
     * @return The random salt suitable for generateKeyPair.
     */
    public static byte[] generateSalt() throws GeneralSecurityException {        
        return CryptorFunctions.getRandomBytes(SECRETKEY_DERIVATION_SALT_SIZE_BYTE);
    } 
}
