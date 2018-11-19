/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.symmetric;

import org.encryption.custom.CryptorFunctions;
import org.encryption.custom.Functions;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCBC {
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
    //Java only supports AES encryption with 128 bit keys out of the box –
    //  if you want 192 or 256 bit keys then you need to install the 
    //  “Java JCE Unlimited Strength Jurisdiction Policy Files” for your version of Java. 
    //  Every user of your tool will need to install them as well.
    public static final int SECRETKEY_DERIVATION_SIZE_BIT = 128;
    
    public static final int SECRETKEY_DERIVATION_SALT_SIZE_BYTE = 20;
    
    public static final int INITIALIZATION_VECTOR_SIZE_BYTE = 16;
    
    //Iteration count is the number of times that the password is hashed during the derivation 
    //of the symmetric key. The higher number, the more difficult it is to brute force the key. 
    //It is used together with the salt which is used to prevent against attacks using rainbow tables.
    private static final int SECRETKEY_DERIVATION_ITERATIONS = Character.MAX_VALUE*10; //100; 27sec
    
    public static final String SECRETKEY_DERIVATION_ALGORITHM = "AES";
    
    //Modes that require padding: 
    //  Like in the example, padding can generally be dangerous because it opens up 
    //  the possibility of padding oracle attacks. The easiest defense is to authenticate 
    //  every message before decryption. 
    //
    //Encryption only:
    //  * ECB encrypts each block of data independently and the same plaintext block 
    //      will result in the same ciphertext block. Take a look at the ECB encrypted Tux image 
    //      on the ECB Wikipedia page to see why this is a serious problem. 
    //      I don't know of any use case where ECB would be acceptable.
    //
    //  * CBC has an IV and thus needs randomness every time a message is encrypted, 
    //      changing a part of the message requires re-encrypting everything after the change, 
    //      transmission errors in one ciphertext block completely destroy the plaintext and 
    //      change the decryption of the next block, decryption can be parallelized / encryption can't, 
    //      the plaintext is malleable to a certain degree - this can be a problem.
    //
    //Authenticated encryption:
    //  To prevent padding oracle attacks and changes to the ciphertext, 
    //  one can compute a message authentication code (MAC) on the ciphertext and 
    //  only decrypt it if it has not been tampered with. This is called encrypt-then-mac 
    //  and should be preferred to any other order. Except for very few use cases 
    //  authenticity is as important as confidentiality (the latter of which is the aim of encryption). 
    //  Authenticated encryption schemes (with associated data (AEAD)) combine the 
    //  two part process of encryption and authentication into one block cipher mode 
    //  that also produces an authentication tag in the process. 
    //  In most cases this results in speed improvement.
    //
    //  * CCM is a simple combination of CTR mode and a CBC-MAC. 
    //      Using two block cipher encryptions per block it is very slow.
    //
    //  * OCB is faster but encumbered by patents. For free (as in freedom) or 
    //      non-military software the patent holder has granted a free license, though.
    //
    //  * GCM is a very fast but arguably complex combination of CTR mode and GHASH, 
    //      a MAC over the Galois field with 2^128 elements. Its wide use in important 
    //      network standards like TLS 1.2 is reflected by a special instruction 
    //      Intel has introduced to speed up the calculation of GHASH.
    //
    //Recommendation:
    //  Considering the importance of authentication I would recommend the following 
    //  two block cipher modes for most use cases (except for disk encryption purposes): 
    //  If the data is authenticated by an asymmetric signature use CBC, otherwise use GCM.
    public static final String SECRETKEY_CIPHER_WRAP_ALGORITHM = 
            "AES/CBC/PKCS5Padding"
            ;
    
    /**
     * Encrypt string with given key with no integrity check
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
        
        //add init vector 
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
    
    public static SecretKey generateKey(byte[] salt, String password) throws GeneralSecurityException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, SECRETKEY_DERIVATION_ITERATIONS, SECRETKEY_DERIVATION_SIZE_BIT);
        
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(SECRETKEY_DERIVATION_FUNC);
        
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
        
        //Generate the AES key
        SecretKey confidentialityKey = new SecretKeySpec(keyBytes, SECRETKEY_DERIVATION_ALGORITHM);

        return confidentialityKey;
    }
    
    /**
     * Generates a random salt.
     * @return The random salt suitable for generateKeyPair.
     */
    public static byte[] generateSalt() throws GeneralSecurityException {        
        return CryptorFunctions.getRandomBytes(SECRETKEY_DERIVATION_SALT_SIZE_BYTE);
    } 
    
    
}
