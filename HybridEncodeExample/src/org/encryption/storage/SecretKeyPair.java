/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.storage;

import org.encryption.custom.CryptorFunctions;
import org.encryption.custom.Functions;
import org.encryption.symmetric.AESCBCIntegrity;
import java.io.IOException;
import java.security.InvalidKeyException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author colt
 */
/**
     * Holder class that has both the secret AES key for encryption (confidentiality)
     * and the secret HMAC key for integrity.
     */

public class SecretKeyPair {
    private final String BYTE_ENCODING = 
            "BASE64"
            //"HEX"
            ;
    //Confidentiality
    //  More commonly, the biggest concern will be to keep information private. 
    //  Cryptographic systems were originally developed to function in this capacity. 
    //  Whether it be passwords sent during a log on process, or storing confidential medical 
    //  records in a database, encryption can assure that only users who have access 
    //  to the appropriate key will get access to the data.
    private SecretKey confidentialityKey;
    //Integrity
    //  We can use cryptography to provide a means to ensure data is not viewed or altered 
    //  during storage or transmission. Cryptographic hashes for example, can safeguard data 
    //  by providing a secure checksum.
    private SecretKey integrityKey;

    /**
     * Construct the secret keys container.
     * @param confidentialityKeyIn The AES key
     * @param integrityKeyIn the HMAC key
     */
    public SecretKeyPair(SecretKey confidentialityKeyIn, SecretKey integrityKeyIn) {
        setConfidentialityKey(confidentialityKeyIn);
        setIntegrityKey(integrityKeyIn);
    }
    
    public SecretKeyPair() {
    }

    public SecretKey getConfidentialityKey() {
        return confidentialityKey;
    }

    public void setConfidentialityKey(SecretKey confidentialityKey) {
        this.confidentialityKey = confidentialityKey;
    }

    public SecretKey getIntegrityKey() {
        return integrityKey;
    }

    public void setIntegrityKey(SecretKey integrityKey) {
        this.integrityKey = integrityKey;
    }

    /**
     * Encodes the two keys as a string
     * @return base64(confidentialityKey):base64(integrityKey)
     */
    @Override
    public String toString () {        
        if(BYTE_ENCODING.equalsIgnoreCase("HEX")) 
            return toStringHEX();
        
        else if(BYTE_ENCODING.equalsIgnoreCase("BASE64")) 
            return toStringBASE64();
        
        else 
            return null;
    }
    
    public String toStringBASE64 () {
        try {
            return Functions.byte2Base64(getConfidentialityKey().getEncoded())
                    + ":" +  Functions.byte2Base64(getIntegrityKey().getEncoded());
        } catch (IOException ex) {
            System.out.println("Ex#"+ex);
        }
        return null;
    }
    
    public String toStringHEX () {
        return Functions.byte2Hex(getConfidentialityKey().getEncoded())
                +   Functions.byte2Hex(getIntegrityKey().getEncoded());
    }
    
    /**
     * An aes key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     *
     * @param keysStr a base64 encoded AES key / hmac key as base64(aesKey) : base64(hmacKey).
     * @return an AES & HMAC key set suitable for other functions.
     */
    public SecretKeyPair toObject(String encodedString) throws IOException, InvalidKeyException{
        if(BYTE_ENCODING.equalsIgnoreCase("HEX")) 
            return toObjectFromHEX(encodedString); 
        
        else if(BYTE_ENCODING.equalsIgnoreCase("BASE64")) 
            return toObjectFromBASE64(encodedString);
        
        else 
            return null;    
    }
    
    public SecretKeyPair toObjectFromBASE64(String base64String) throws IOException, InvalidKeyException{
        String[] keysArr = base64String.split(":");
        
        if (keysArr.length != 2) {
            throw new IllegalArgumentException("Cannot parse aesKey:hmacKey");

        } else {
            byte[] confidentialityKey = Functions.base642Byte(keysArr[0]);
            if (confidentialityKey.length != AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT /8) {
                throw new InvalidKeyException("Base64 decoded key is not " + AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT + " bytes");
            }
            byte[] integrityKey = Functions.base642Byte(keysArr[1]);
            if (integrityKey.length != CryptorFunctions.HMAC_KEY_LENGTH_BITS /8) {
                throw new InvalidKeyException("Base64 decoded key is not " + CryptorFunctions.HMAC_KEY_LENGTH_BITS + " bytes");
            }

            return new SecretKeyPair(
                    new SecretKeySpec(confidentialityKey, 0, confidentialityKey.length, AESCBCIntegrity.SECRETKEY_DERIVATION_ALGORITHM),
                    new SecretKeySpec(integrityKey, CryptorFunctions.HMAC_ALGORITHM));
        }     
    }
    
    public SecretKeyPair toObjectFromHEX(String hexString) throws IOException, InvalidKeyException{
        byte[] stringBytes = Functions.hex2Byte(hexString);
        if(stringBytes.length != (CryptorFunctions.HMAC_KEY_LENGTH_BITS+AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT)/8 )
            throw new IllegalArgumentException("Keypair Length not valid:"+stringBytes.length);
        
        int offset = AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT/8;
        byte[] confidentialityKey   = Functions.byteCopy(stringBytes, 0, offset);
                
        byte[] integrityKey         = Functions.byteCopy(stringBytes, offset, stringBytes.length);
        
        return new SecretKeyPair(
                new SecretKeySpec(confidentialityKey, 0, confidentialityKey.length, AESCBCIntegrity.SECRETKEY_DERIVATION_ALGORITHM),
                new SecretKeySpec(integrityKey, CryptorFunctions.HMAC_ALGORITHM));   
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + confidentialityKey.hashCode();
        result = prime * result + integrityKey.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SecretKeyPair other = (SecretKeyPair) obj;
        //if (!integrityKey.equals(other.integrityKey))
        if(Functions.byteArrConstTimeEquality(integrityKey.getEncoded(), other.integrityKey.getEncoded()))
            return false;
        if(Functions.byteArrConstTimeEquality(confidentialityKey.getEncoded(), other.confidentialityKey.getEncoded()))
        //if (!confidentialityKey.equals(other.confidentialityKey))
            return false;
        return true;
    }
}
