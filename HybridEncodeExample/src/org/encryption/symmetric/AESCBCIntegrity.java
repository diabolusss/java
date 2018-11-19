/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.symmetric;

import org.encryption.custom.CryptorFunctions;
import org.encryption.custom.Functions;
import org.encryption.storage.MACIVCipher;
import org.encryption.storage.SecretKeyPair;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple library for the "right" defaults for AES key generation, encryption,
 * and decryption using 128-bit AES, CBC, PKCS5 padding, and a random 16-byte IV
 * with SHA1PRNG. Integrity with HmacSHA256.
 * 
 * Taken from here: http://tozny.com/blog/encrypting-strings-in-android-lets-make-better-mistakes/
 *  https://github.com/tozny/java-aes-crypto
 * 
 * Don't use encryption without message authentication
 *  It is a very common error to encrypt data without also authenticating it.
 *  Example:
 *      The developer wants to keep a message secret, so encrypts the message with AES-CBC mode. 
 *      The error: 
 *          This is not sufficient for security in the presence of active attacks, 
 *          replay attacks, reaction attacks, etc. There are known attacks on encryption
 *          without message authentication, and the attacks can be quite serious. 
 *          The fix is to add message authentication.
 * 
 *  This mistake has led to serious vulnerabilities in deployed systems that used
 *  encryption without authentication, including ASP.NET, XML encryption, Amazon EC2, 
 *  JavaServer Faces, Ruby on Rails, OWASP ESAPI, IPSEC, WEP, ASP.NET again, and SSH2. 
 *  You don't want to be the next one on this list.
 * 
 *  To avoid these problems, you need to use message authentication every time you apply encryption.
 *  You have two choices for how to do that:
 * 
 *  * Probably the simplest solution is to use an encryption scheme that provides authenticated encryption,
 *      e.g.., GCM, CWC, EAX, CCM, OCB. (See also: 1.) 
 *      The authenticated encryption scheme handles this for you, so you don't have to think about it.
 * 
 *  * Alternatively, you can apply your own message authentication, as follows. 
 *      First, encrypt the message using an appropriate symmetric-key encryption scheme (e.g., AES-CBC). 
 *      Then, take the entire ciphertext (including any IVs, nonces, or other values needed for decryption), 
 *      apply a message authentication code (e.g., AES-CMAC, SHA1-HMAC, SHA256-HMAC), 
 *      and append the resulting MAC digest to the ciphertext before transmission. 
 *      On the receiving side, check that the MAC digest is valid before decrypting. 
 *      This is known as the encrypt-then-authenticate construction. (See also: 1, 2.) 
 *      This also works fine, but requires a little more care from you.
 * 
 * Data Tampering
 *  Data tampering attack is possible only if the attacker already knows the content 
 *  of encrypted message. Such attacker can change first message block to whatever he wishes to.
 * 
 *  In particular, it is possible to: 
 *      - change first 16 bytes of AES-CBC encrypted message,
 *      - change first 8 bytes of Blowfish-CBC encrypted message.
 * 
 * Potential Danger
 *  Whether this type of attack is dangerous depends a lot on circumstances. 
 *  If you use the cipher to send password through network, then data tampering is not so dangerous.
 *  At worst, a legitimate user will get login denied. Similarly, if your
 *  encrypted data are stored on some read-only storage, then you 
 *  do not have to worry about data tampering. 
 *  However, if you are sending bank order through the network, 
 *  data tampering is a real threat. If someone changes the message Pay Mark 100$ 
 *  into Pay Tom 9999$, Tom will get 9999$ he should not get.
 * 
 * И CBC, и CTR подвержены элементарным атакам на целостность данных, поэтому в чистом виде не используются.
 * Но если добавить код проверки аутентичности сообщения GMAC к режиму работы блочного шифра CTR, 
 * получится… режим GCM, который рекламируется самим NSA и вами.
 */
public class AESCBCIntegrity {
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
            //"AES/GCM/NoPadding"
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
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the MACIVCipher class.
     *
     * @param plaintext The text that will be encrypted
     * @param secretKeys The combined AES & HMAC restoreKeyPair with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    public static MACIVCipher encrypt(byte[] plaintext, SecretKeyPair secretKeys)  throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(SECRETKEY_CIPHER_WRAP_ALGORITHM);
        
        //generate initialization vector
        //byte[] iv = AESCBCIntegrity.generateIV();
        //In the case of AES, a block is 16 bytes, or 128 bits. 
        //In cryptography, an initialization vector (IV) or starting variable (SV)[1] 
        //is a fixed-size input to a cryptographic primitive that is typically required to be random or pseudorandom
        byte[] iv = CryptorFunctions.getRandomBytes(aesCipher.getBlockSize());
        
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeys.getConfidentialityKey(), new IvParameterSpec(iv));

        
        // * Now we get back the IV that will actually be used. Some Android
        // * versions do funny stuff w/ the IV, so this is to workaround bugs:
        iv = aesCipher.getIV();
        
        //finalize encode
        byte[] encodedText = aesCipher.doFinal(plaintext);
        
        //save init vector for decoding this message 
        //An initialization vector has different security requirements than a key, 
        //  so the IV usually does not need to be secret. However, in most cases, it is important 
        //  that an initialization vector is never reused under the same key. For CBC and CFB, 
        //  reusing an IV leaks some information about the first block of plaintext, 
        //  and about any common prefix shared by the two messages.
        byte[] ivCipherConcat = Functions.byteConcat(iv, encodedText);

        //generate MAC
        //A MAC provides a way to check the integrity of information transmitted over 
        //  or stored in an unreliable medium, based on a secret key
        //  A MAC is a Message Authentication Code. It is the symmetric key equivalent 
        //  of a digital signature (a digital signature exists in the Public Key/Private Key realm). 
        //  MACs provide assurances on authenticity and origin. If we receive a ciphertext and the 
        //  MAC over the ciphertext is valid, we presume with very high probability 
        //  that the message came from our peer and has not been tampered.
        byte[] integrityMac = CryptorFunctions.generateMAC(ivCipherConcat, secretKeys.getIntegrityKey());
        
        return new MACIVCipher(encodedText, iv, integrityMac);
    }
    
    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the MACIVCipher class.
     *
     * @param plaintext The bytes that will be encrypted
     * @param secretKeys The AES & HMAC restoreKeyPair with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the specified encoding is invalid
     */
    public static MACIVCipher encrypt(String plaintext, SecretKeyPair secretKeys, String encoding)            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext.getBytes(encoding), secretKeys);
    }
    
    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the MACIVCipher class.
     *
     * @param plaintext The text that will be encrypted, which
     *                  will be serialized with UTF-8
     * @param secretKeys The AES & HMAC restoreKeyPair with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported in this system
     */
    public static MACIVCipher encrypt(String plaintext, SecretKeyPair secretKeys)            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext, secretKeys, "UTF-8");
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
     * AES CBC decrypt.
     *
     * @param civ the cipher text, iv, and mac
     * @param secretKeys the AES & HMAC restoreKeyPair
     * @return The raw decrypted bytes
     * @throws GeneralSecurityException if MACs don't match or AES is not implemented
     */
    public static byte[] decrypt(MACIVCipher civ, SecretKeyPair secretKeys)            throws GeneralSecurityException {

        byte[] ivCipherConcat = Functions.byteConcat(civ.getIv(), civ.getCipherText());
        
        byte[] computedMac = CryptorFunctions.generateMAC(ivCipherConcat, secretKeys.getIntegrityKey());
        
        //if computed mac is the same as received - message is valid
        if (Functions.byteArrConstTimeEquality(computedMac, civ.getMac())) {
            Cipher aesCipherForDecryption = Cipher.getInstance(SECRETKEY_CIPHER_WRAP_ALGORITHM);
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKeys.getConfidentialityKey(), new IvParameterSpec(civ.getIv()));
            
            return aesCipherForDecryption.doFinal(civ.getCipherText());
            
        } else {
            throw new GeneralSecurityException("MAC stored in civ does not match computed MAC.");
        }
    }    
    
    
    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The AES & HMAC restoreKeyPair
     * @return A string derived from the decrypted bytes, which are interpreted
     *         as a UTF-8 String
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported
     */
    public static String decrypt2String(MACIVCipher civ, SecretKeyPair secretKeys)            throws UnsupportedEncodingException, GeneralSecurityException {
        return decrypt2String(civ, secretKeys, "UTF-8");
    }
    
    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The AES & HMAC restoreKeyPair
     * @param encoding The string encoding to use to decode the bytes after decryption
     * @return A string derived from the decrypted bytes (not base64 encoded)
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the encoding is unsupported
     */
    public static String decrypt2String(MACIVCipher civ, SecretKeyPair secretKeys, String encoding)            throws UnsupportedEncodingException, GeneralSecurityException {
        return new String(decrypt(civ, secretKeys), encoding);
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
     * A function that generates random AES & HMAC keys and prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     * 
     * If you have existing plaintext key material that you must use, then SecretKeyFactory 
     *  is the way you convert that material into a SecretKey object.
     *  However, if you need to generate a new key, use a KeyGenerator.
     * 
     * Before encryption and authentication were joined as a single cryptographic operation, 
     * a system would usually encrypt the data under a first key, and 
     * then make a second pass over the data using a second key. 
     *
     * Keys must be independent - using the same key to both encrypt the data and 
     * authenticate the data (which would allow a single pass over the data) 
     * causes the ciphertext to be independent of the plaintext. 
     * So the authentication mechanism is rendered completely insecure [Handbook of Applied Cryptography, p.367]
     * 
     * CBC with XOR Checksum (CBCC) - insecure due to defects in the authentication mechanism [p.368] 
     * CBC with mod 2n-1 Checksum - insecure due to chosen-plaintext attacks [p.368] 
     * Plaintext-Ciphertext Block Chaining (PCBC) - insecure due to known-plaintext attacks [p.368] 
     * CBC-Pad - insecure for variable message lengths [17]
     * 
     * @return The AES & HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKeyPair generateKeyPair() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance(SECRETKEY_DERIVATION_ALGORITHM);
        // No need to provide a SecureRandom or set a seed since that will
        // happen automatically.
        keyGen.init(SECRETKEY_DERIVATION_SIZE_BIT);
        SecretKey confidentialityKey = keyGen.generateKey();

        //Now make the HMAC key
        byte[] integrityKeyBytes = CryptorFunctions.getRandomBytes(CryptorFunctions.HMAC_KEY_LENGTH_BITS / 8);//to get bytes
        SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, CryptorFunctions.HMAC_ALGORITHM);

        return new SecretKeyPair(confidentialityKey, integrityKey);
    }
    
    /**
     * A function that generates password-based AES & HMAC restoreKeyPair. It prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @param password The password to derive the restoreKeyPair from.
     * @return The AES & HMAC restoreKeyPair.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKeyPair generateKeyPair(String password, byte[] salt) throws GeneralSecurityException {
        //Get enough random bytes for both the AES key and the HMAC key:
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, SECRETKEY_DERIVATION_ITERATIONS, SECRETKEY_DERIVATION_SIZE_BIT + CryptorFunctions.HMAC_KEY_LENGTH_BITS);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(SECRETKEY_DERIVATION_FUNC);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        // Split the random bytes into two parts:
        byte[] confidentialityKeyBytes = Functions.byteCopy(keyBytes, 0, SECRETKEY_DERIVATION_SIZE_BIT /8);
        byte[] integrityKeyBytes = Functions.byteCopy(keyBytes, SECRETKEY_DERIVATION_SIZE_BIT /8, SECRETKEY_DERIVATION_SIZE_BIT /8 + CryptorFunctions.HMAC_KEY_LENGTH_BITS /8);

        //Generate the AES key
        SecretKey confidentialityKey = new SecretKeySpec(confidentialityKeyBytes, SECRETKEY_DERIVATION_ALGORITHM);

        //Generate the HMAC key
        SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, CryptorFunctions.HMAC_ALGORITHM);

        return new SecretKeyPair(confidentialityKey, integrityKey);
    }
    
    /**
     * A function that generates password-based AES & HMAC restoreKeyPair. See generateKeyPair.
     * @param password The password to derive the AES/HMAC restoreKeyPair from
     * @param salt A string version of the salt; base64 encoded.
     * @return The AES & HMAC restoreKeyPair.
     * @throws GeneralSecurityException
     */
    public static SecretKeyPair generateKeyPair(String password, String salt) throws GeneralSecurityException, IOException {
        return generateKeyPair(password, Functions.base642Byte(salt));
    }
    
    /**
     * Generates a random salt.
     * @return The random salt suitable for generateKeyPair.
     */
    public static byte[] generateSalt() throws GeneralSecurityException {        
        return CryptorFunctions.getRandomBytes(SECRETKEY_DERIVATION_SALT_SIZE_BYTE);
    } 
    
    
}
