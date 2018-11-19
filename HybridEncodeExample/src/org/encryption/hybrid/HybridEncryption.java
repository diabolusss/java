/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.hybrid;

import org.encryption.custom.CryptorFunctions;
import org.encryption.symmetric.AESGCM;
import org.encryption.custom.Functions;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 *
 * @author colt
 */
public class HybridEncryption {
    /**
     * Generate symmetric AES key from password and random salt
     * and wrap RSA private key with generated key. Finally, save salt by concatinating it
     * the wrapped key
     * @param passphrase
     * @param rsaPrivateKey
     * @return
     * @throws UnsupportedEncodingException 
     */
    public static byte[] encryptRSAAESRand(final String passphrase, final RSAPrivateKey rsaPrivateKey) throws UnsupportedEncodingException, GeneralSecurityException {
        // --- generate salt
        final byte[] newSalt = AESGCM.generateSalt();
        
        // --- derive symmetric key from salt and password
        final SecretKey aesKey = AESGCM.generateKey(newSalt, passphrase.toCharArray());

        //wrap assymetric private key for secure storage
        final byte[] encryptedPrivate = AESGCM.wrapPrivateKeyRSA(rsaPrivateKey, aesKey);
        
        //and concat salt for symmetric key restore
        //Generally, the salt is stored with the encrypted text. 
        //It is also generally stored in clear form -- not encrypted. 
        //Believe it or not, there is no reason to protect the salt.
        final byte[] saltedAndEncryptedPrivate = Functions.byteConcat(newSalt,encryptedPrivate);
        
        return saltedAndEncryptedPrivate;
    }    

    /**
     * Decode RSA private key. Firstly, extract salt to restore AES key and then decode key using restored key.
     * @param passphrase
     * @param saltedAndEncryptedPrivate
     * @return
     * @throws InvalidKeyException 
     */
    public static RSAPrivateKey decryptRSAAESRand(final String passphrase, final byte[] saltedAndEncryptedPrivate) throws InvalidKeyException {
        int offset = AESGCM.SECRETKEY_DERIVATION_SALT_SIZE_BYTE;
        final byte[] restoredSalt = Arrays.copyOfRange(saltedAndEncryptedPrivate, 0, offset);
        
        final SecretKey restoredAESKey = AESGCM.generateKey(restoredSalt, passphrase.toCharArray());
        
        final byte[] restoredEncryptedPrivateKey = Arrays.copyOfRange(saltedAndEncryptedPrivate, offset,saltedAndEncryptedPrivate.length);
        
        final RSAPrivateKey decryptedPrivate = AESGCM.unwrapPrivateKeyRSA(restoredEncryptedPrivateKey, restoredAESKey);
        
        return decryptedPrivate;
    }
}
