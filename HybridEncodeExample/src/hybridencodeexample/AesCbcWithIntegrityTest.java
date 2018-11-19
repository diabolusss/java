/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package hybridencodeexample;

import custom.PRNGFixes;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import org.encryption.storage.MACIVCipher;
import org.encryption.symmetric.AESCBCIntegrity;
import org.encryption.custom.Functions;
import org.encryption.storage.SecretKeyPair;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.encryption.symmetric.AESCBC;
import org.encryption.symmetric.AESGCM;
import org.encryption.symmetric.AESGCMIntegrity;

/**
 *
 * @author colt
 */
public class AesCbcWithIntegrityTest {
    public static String password = "/DTyvbbn8ka6sVD4jjfXD5AFwTm59oWismYfXDa98X4=";
    public static String textToEncrypt = 
        "\nWe, the Fairies, blithe and antic,\n" +
        "Of dimensions not gigantic,\n" +
        "Though the moonshine mostly keep us,\n" +
        "Oft in orchards frisk and peep us. ";
    
    public static String textToEncrypt2 = 
        "\nAre IV's always public knowledge? Well, they don't have to be public knowledge.\n "
            + "However, they can be, and because the easiest way to transport them from encryptor to \n"
            + "decryptor is just include them in the ciphertext, they usually are.\n"
            +"Given that IV are often public, are there any attacks that involve a man-in-the-middle \n"
            + "attack that alters the IV? Well, I would hope that any encryption mechanism would also\n"
            + " include an integrity check which should catch this. If this check is on the plaintext, \n"
            + "any change in the IV will also modify the plaintext, and so it will check this. \n"
            + "If this check is on the ciphertext, the check will need to include a check on the IV.";
    
    /**
     * Ensures that the PRNG is fixed. Should be used before generating any restoreKeyPair.
     * Will only run once, and every subsequent call should return immediately.
     */    
    private static final AtomicBoolean PRNG_FIXED = new AtomicBoolean(false);
    
    public static void fixPrng() {
        if (!PRNG_FIXED.get()) {
            synchronized (PRNGFixes.class) {
                if (!PRNG_FIXED.get()) {
                    PRNGFixes.apply();
                    PRNG_FIXED.set(true);
                }
            }
        }
    }
    
    public static void main(final String[] args) throws Exception {        
        fixPrng();
        // --- not required for Java 8
        Security.addProvider(new BouncyCastleProvider());
        
        // For instance, with TLS 1.2, a session key is created during the tunnel setup (the "handshake"), 
        //then data is encrypted as so many "records" (up to 16 kB of data per record) and each record has its own IV.
        
        /*String[] encryptedPassword = StringCryptor.encrypt( password, "string to encrypt" ); 

        System.out.println("EncryptedData(ContainedData)["+encryptedPassword[0].length()+"] :"+encryptedPassword[0]);
        System.out.println("EncryptedData(salt)["+encryptedPassword[1].length()+"] :"+encryptedPassword[1]);
        
        String decripted = StringCryptor.decrypt( "password", encryptedPassword[1], encryptedPassword[0] );
        
        System.out.println("EncryptedData["+decripted.length()+"] :"+decripted);
        */
        {//simple encode
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            System.out.println("++++++                                       ++++++++"); 
            System.out.println("++++++ ENCODING WITHOUT INTEGRITY CHECK  "+AESGCM.SECRETKEY_CIPHER_WRAP_ALGORITHM+"    ++++++++");            
            System.out.println("++++++                                       ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++");             
            System.out.println("++++++   To decode received encoded message  ++++++++"); 
            System.out.println("++++++   you need to know salt and pass      ++++++++");            
            System.out.println("++++++   to restore SecretKey                ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            byte[] salt = AESGCM.generateSalt();

            String saltBase64 = Functions.byte2Base64(salt);	
            System.out.println("saltBase64["+saltBase64.length()+"] :"+saltBase64);
            String saltHex = Functions.byte2Hex(salt);		
            System.out.println("saltHex["+saltHex.length()+"] :"+saltHex);

            SecretKey key = AESGCM.generateKey(salt, password);            
            
            // The encryption / storage & display:        
            byte[] encrypted = AESGCM.encrypt(textToEncrypt.getBytes("UTF-8"), key);
            String encryptedDataBase64 = Functions.byte2Base64(encrypted);
            System.out.println("encryptedDataBase64["+encryptedDataBase64.length()+"] :"+encryptedDataBase64);
            String encryptedDataHex = Functions.byte2Hex(encrypted);
            System.out.println("encryptedDataHex["+encryptedDataHex.length()+"] :"+encryptedDataHex);

            SecretKey restoredKey = AESGCM.generateKey(salt, password);
            System.out.println("\t restoredKeyHEX["+Functions.byte2Hex(restoredKey.getEncoded()).length()+"] :"+Functions.byte2Hex(restoredKey.getEncoded()));
            System.out.println("\t restoredKeyByte["+restoredKey.getEncoded().length+"] :"+restoredKey.getEncoded());
            
            
            byte[] decrypted = AESGCM.decrypt(encrypted, restoredKey);
            String decryptedText = new String(decrypted, "UTF-8");
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);  
            
            System.out.println("----------->encryptionBase64 overhead: "+(double)encryptedDataBase64.length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)encryptedDataHex.length()/decryptedText.length());
        
            
            encrypted = AESGCM.encrypt(textToEncrypt2.getBytes("UTF-8"), key);
            encryptedDataBase64 = Functions.byte2Base64(encrypted);
            System.out.println("encryptedDataBase64["+encryptedDataBase64.length()+"] :"+encryptedDataBase64);
            encryptedDataHex = Functions.byte2Hex(encrypted);
            System.out.println("encryptedDataHex["+encryptedDataHex.length()+"] :"+encryptedDataHex);

            restoredKey = AESGCM.generateKey(salt, password);
            
            decrypted = AESGCM.decrypt(encrypted, restoredKey);
            decryptedText = new String(decrypted, "UTF-8");
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);
            
            System.out.println("----------->encryptionBase64 overhead: "+(double)encryptedDataBase64.length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)encryptedDataHex.length()/decryptedText.length());
        }
        
        
        {//simple encode
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            System.out.println("++++++                                       ++++++++"); 
            System.out.println("++++++ ENCODING WITHOUT INTEGRITY CHECK  "+AESCBC.SECRETKEY_CIPHER_WRAP_ALGORITHM+"    ++++++++");            
            System.out.println("++++++                                       ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++");             
            System.out.println("++++++   To decode received encoded message  ++++++++"); 
            System.out.println("++++++   you need to know salt and pass      ++++++++");            
            System.out.println("++++++   to restore SecretKey                ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            byte[] salt = AESCBC.generateSalt();

            String saltBase64 = Functions.byte2Base64(salt);	
            System.out.println("saltBase64["+saltBase64.length()+"] :"+saltBase64);
            String saltHex = Functions.byte2Hex(salt);		
            System.out.println("saltHex["+saltHex.length()+"] :"+saltHex);

            SecretKey key = AESCBC.generateKey(salt, password);            
            
            // The encryption / storage & display:        
            byte[] encrypted = AESCBC.encrypt(textToEncrypt.getBytes("UTF-8"), key);
            String encryptedDataBase64 = Functions.byte2Base64(encrypted);
            System.out.println("encryptedDataBase64["+encryptedDataBase64.length()+"] :"+encryptedDataBase64);
            String encryptedDataHex = Functions.byte2Hex(encrypted);
            System.out.println("encryptedDataHex["+encryptedDataHex.length()+"] :"+encryptedDataHex);

            SecretKey restoredKey = AESCBC.generateKey(salt, password);
            System.out.println("\t restoredKeyHEX["+Functions.byte2Hex(restoredKey.getEncoded()).length()+"] :"+Functions.byte2Hex(restoredKey.getEncoded()));
            System.out.println("\t restoredKeyByte["+restoredKey.getEncoded().length+"] :"+restoredKey.getEncoded());
            
            
            byte[] decrypted = AESCBC.decrypt(encrypted, restoredKey);
            String decryptedText = new String(decrypted, "UTF-8");
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);  
            
            System.out.println("----------->encryptionBase64 overhead: "+(double)encryptedDataBase64.length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)encryptedDataHex.length()/decryptedText.length());
        
            
            encrypted = AESCBC.encrypt(textToEncrypt2.getBytes("UTF-8"), key);
            encryptedDataBase64 = Functions.byte2Base64(encrypted);
            System.out.println("encryptedDataBase64["+encryptedDataBase64.length()+"] :"+encryptedDataBase64);
            encryptedDataHex = Functions.byte2Hex(encrypted);
            System.out.println("encryptedDataHex["+encryptedDataHex.length()+"] :"+encryptedDataHex);

            restoredKey = AESCBC.generateKey(salt, password);
            
            decrypted = AESCBC.decrypt(encrypted, restoredKey);
            decryptedText = new String(decrypted, "UTF-8");
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);
            
            System.out.println("----------->encryptionBase64 overhead: "+(double)encryptedDataBase64.length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)encryptedDataHex.length()/decryptedText.length());
        }
        
        
        {//encode with integrity
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            System.out.println("++++++ ENCODING WITH INTEGRITY CHECK   "+AESCBCIntegrity.SECRETKEY_CIPHER_WRAP_ALGORITHM+"      ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++");            
            System.out.println("++++++   To decode received encoded message  ++++++++"); 
            System.out.println("++++++   you need to know salt and pass      ++++++++");            
            System.out.println("++++++   to restore SecretKeyPair            ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            
            byte[] salt = AESCBCIntegrity.generateSalt();

            String saltBase64 = Functions.byte2Base64(salt);	
            System.out.println("saltBase64["+saltBase64.length()+"] :"+saltBase64);
            String saltHex = Functions.byte2Hex(salt);		
            System.out.println("saltHex["+saltHex.length()+"] :"+saltHex);

            SecretKeyPair key = AESCBCIntegrity.generateKeyPair(password, saltBase64);
            String secretKeyPairStorage = key.toString();
            System.out.println("secretKeyPairStorageBase64["+key.toStringBASE64().length()+"] :"+key.toStringBASE64());   
            System.out.println("secretKeyPairStorageHex["+key.toStringHEX().length()+"] :"+key.toStringHEX());
            System.out.println("\t getConfidentialityKeyHEX["+Functions.byte2Hex(key.getConfidentialityKey().getEncoded()).length()+"] :"+Functions.byte2Hex(key.getConfidentialityKey().getEncoded()));
            System.out.println("\t getConfidentialityKeyByte["+key.getConfidentialityKey().getEncoded().length+"] :"+key.getConfidentialityKey().getEncoded());
            System.out.println("\t getIntegrityKeyByte["+key.getIntegrityKey().getEncoded().length+"] :"+key.getIntegrityKey().getEncoded());
            System.out.println("\t getIntegrityKeyHEX["+Functions.byte2Hex(key.getIntegrityKey().getEncoded()).length()+"] :"+Functions.byte2Hex(key.getIntegrityKey().getEncoded()));
            
            // The encryption / storage & display:        
            MACIVCipher civ = AESCBCIntegrity.encrypt(textToEncrypt, key);
            String encryptedData = civ.toString();
            System.out.println("encryptedDataStorageBase64["+civ.toStringBASE64().length()+"] :"+civ.toStringBASE64());
            System.out.println("encryptedDataStorageHEX["+civ.toStringHEX().length()+"] :"+civ.toStringHEX());
            System.out.println("\tgetCipherTextHex["+Functions.byte2Hex(civ.getCipherText()).length()+"] :"+Functions.byte2Hex(civ.getCipherText()) );
            System.out.println("\tgetIvHex["+Functions.byte2Hex(civ.getIv()).length()+"] :"+Functions.byte2Hex(civ.getIv()) );
            System.out.println("\tgetMacHex["+Functions.byte2Hex(civ.getMac()).length()+"] :"+Functions.byte2Hex(civ.getMac()) );
            System.out.println("\tgetCipherTextByte["+civ.getCipherText().length+"] :"+civ.getCipherText() );
            System.out.println("\tgetIvByte["+civ.getIv().length+"] :"+civ.getIv() );
            System.out.println("\tgetMacByte["+civ.getMac().length+"] :"+civ.getMac() );


            SecretKeyPair regenerateKey = new SecretKeyPair();
            regenerateKey = regenerateKey.toObject(secretKeyPairStorage);
                    //CryptorAESCBCIntegrity.generateKeyPair(password, saltBase64);

            MACIVCipher receivedData = new MACIVCipher(encryptedData);

            String decryptedText = AESCBCIntegrity.decrypt2String(receivedData, regenerateKey);
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);
            System.out.println("----------->encryptionBase64 overhead: "+(double)civ.toStringBASE64().length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)civ.toStringHEX().length()/decryptedText.length());
        
            civ = AESCBCIntegrity.encrypt(textToEncrypt2, key);
            encryptedData = civ.toString();
            System.out.println("encryptedDataStorageBase64["+civ.toStringBASE64().length()+"] :"+civ.toStringBASE64());
            System.out.println("encryptedDataStorageHEX["+civ.toStringHEX().length()+"] :"+civ.toStringHEX());
            System.out.println("\tgetCipherTextHex["+Functions.byte2Hex(civ.getCipherText()).length()+"] :"+Functions.byte2Hex(civ.getCipherText()) );
            System.out.println("\tgetIvHex["+Functions.byte2Hex(civ.getIv()).length()+"] :"+Functions.byte2Hex(civ.getIv()) );
            System.out.println("\tgetMacHex["+Functions.byte2Hex(civ.getMac()).length()+"] :"+Functions.byte2Hex(civ.getMac()) );
            System.out.println("\tgetCipherTextByte["+civ.getCipherText().length+"] :"+civ.getCipherText() );
            System.out.println("\tgetIvByte["+civ.getIv().length+"] :"+civ.getIv() );
            System.out.println("\tgetMacByte["+civ.getMac().length+"] :"+civ.getMac() );


            receivedData = new MACIVCipher(encryptedData);

            decryptedText = AESCBCIntegrity.decrypt2String(receivedData, regenerateKey);
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);
            System.out.println("----------->encryptionBase64 overhead: "+(double)civ.toStringBASE64().length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)civ.toStringHEX().length()/decryptedText.length());
        
        }
        
        {//encode with integrity
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            System.out.println("++++++ ENCODING WITH INTEGRITY CHECK   "+AESGCMIntegrity.SECRETKEY_CIPHER_WRAP_ALGORITHM+"      ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++");            
            System.out.println("++++++   To decode received encoded message  ++++++++"); 
            System.out.println("++++++   you need to know salt and pass      ++++++++");            
            System.out.println("++++++   to restore SecretKeyPair            ++++++++"); 
            System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++"); 
            
            byte[] salt = AESGCMIntegrity.generateSalt();

            String saltBase64 = Functions.byte2Base64(salt);	
            System.out.println("saltBase64["+saltBase64.length()+"] :"+saltBase64);
            String saltHex = Functions.byte2Hex(salt);		
            System.out.println("saltHex["+saltHex.length()+"] :"+saltHex);

            SecretKeyPair key = AESGCMIntegrity.generateKeyPair(password, saltBase64);
            String secretKeyPairStorage = key.toString();
            System.out.println("secretKeyPairStorageBase64["+key.toStringBASE64().length()+"] :"+key.toStringBASE64());   
            System.out.println("secretKeyPairStorageHex["+key.toStringHEX().length()+"] :"+key.toStringHEX());
            System.out.println("\t getConfidentialityKeyHEX["+Functions.byte2Hex(key.getConfidentialityKey().getEncoded()).length()+"] :"+Functions.byte2Hex(key.getConfidentialityKey().getEncoded()));
            System.out.println("\t getConfidentialityKeyByte["+key.getConfidentialityKey().getEncoded().length+"] :"+key.getConfidentialityKey().getEncoded());
            System.out.println("\t getIntegrityKeyByte["+key.getIntegrityKey().getEncoded().length+"] :"+key.getIntegrityKey().getEncoded());
            System.out.println("\t getIntegrityKeyHEX["+Functions.byte2Hex(key.getIntegrityKey().getEncoded()).length()+"] :"+Functions.byte2Hex(key.getIntegrityKey().getEncoded()));
            
            // The encryption / storage & display:        
            MACIVCipher civ = AESGCMIntegrity.encrypt(textToEncrypt, key);
            String encryptedData = civ.toString();
            System.out.println("encryptedDataStorageBase64["+civ.toStringBASE64().length()+"] :"+civ.toStringBASE64());
            System.out.println("encryptedDataStorageHEX["+civ.toStringHEX().length()+"] :"+civ.toStringHEX());
            System.out.println("\tgetCipherTextHex["+Functions.byte2Hex(civ.getCipherText()).length()+"] :"+Functions.byte2Hex(civ.getCipherText()) );
            System.out.println("\tgetIvHex["+Functions.byte2Hex(civ.getIv()).length()+"] :"+Functions.byte2Hex(civ.getIv()) );
            System.out.println("\tgetMacHex["+Functions.byte2Hex(civ.getMac()).length()+"] :"+Functions.byte2Hex(civ.getMac()) );
            System.out.println("\tgetCipherTextByte["+civ.getCipherText().length+"] :"+civ.getCipherText() );
            System.out.println("\tgetIvByte["+civ.getIv().length+"] :"+civ.getIv() );
            System.out.println("\tgetMacByte["+civ.getMac().length+"] :"+civ.getMac() );


            SecretKeyPair regenerateKey = new SecretKeyPair();
            regenerateKey = regenerateKey.toObject(secretKeyPairStorage);
                    //CryptorAESGCMIntegrity.generateKeyPair(password, saltBase64);

            MACIVCipher receivedData = new MACIVCipher(encryptedData);

            String decryptedText = AESGCMIntegrity.decrypt2String(receivedData, regenerateKey);
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);
            System.out.println("----------->encryptionBase64 overhead: "+(double)civ.toStringBASE64().length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)civ.toStringHEX().length()/decryptedText.length());
        
            civ = AESGCMIntegrity.encrypt(textToEncrypt2, key);
            encryptedData = civ.toString();
            System.out.println("encryptedDataStorageBase64["+civ.toStringBASE64().length()+"] :"+civ.toStringBASE64());
            System.out.println("encryptedDataStorageHEX["+civ.toStringHEX().length()+"] :"+civ.toStringHEX());
            System.out.println("\tgetCipherTextHex["+Functions.byte2Hex(civ.getCipherText()).length()+"] :"+Functions.byte2Hex(civ.getCipherText()) );
            System.out.println("\tgetIvHex["+Functions.byte2Hex(civ.getIv()).length()+"] :"+Functions.byte2Hex(civ.getIv()) );
            System.out.println("\tgetMacHex["+Functions.byte2Hex(civ.getMac()).length()+"] :"+Functions.byte2Hex(civ.getMac()) );
            System.out.println("\tgetCipherTextByte["+civ.getCipherText().length+"] :"+civ.getCipherText() );
            System.out.println("\tgetIvByte["+civ.getIv().length+"] :"+civ.getIv() );
            System.out.println("\tgetMacByte["+civ.getMac().length+"] :"+civ.getMac() );


            receivedData = new MACIVCipher(encryptedData);

            decryptedText = AESGCMIntegrity.decrypt2String(receivedData, regenerateKey);
            System.out.println("decryptedText["+decryptedText.length()+"] :"+decryptedText);
            System.out.println("----------->encryptionBase64 overhead: "+(double)civ.toStringBASE64().length()/decryptedText.length());
            System.out.println("----------->encryptionHex overhead: "+(double)civ.toStringHEX().length()/decryptedText.length());
        
        }
    }
}
