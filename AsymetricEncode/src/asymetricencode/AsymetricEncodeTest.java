package asymetricencode;

import custom.Functions;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
 
import javax.crypto.Cipher;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
 
public class AsymetricEncodeTest {
 
    public static final String ALGORITHM = "RSA";
    public static final String PRIVATE_KEY_FILE_NAME = "private.key";
    public static final String PUBLIC_KEY_FILE_NAME = "public.key";
 
    
 
    public static void main(String[] args) {
        final String originalText = "Текст для отправки";
        byte[] encryptedText;
        
        try {
            if (!new File(PRIVATE_KEY_FILE_NAME).exists() || !new File(PUBLIC_KEY_FILE_NAME).exists()) {
                Cryptor.generateSessionKeys(PRIVATE_KEY_FILE_NAME, PUBLIC_KEY_FILE_NAME);
                System.out.println("SessionKeyFiles at messanger B were generated.");
            } 
            String publicKey = Functions.byte2Hex(Cryptor.KeyPublicRestoreFromFile(PUBLIC_KEY_FILE_NAME).getEncoded());
            System.out.println("Public key to send to Messanger A["+publicKey.length()+"]: " + publicKey);
            
            System.out.println("Hash part of public key(so that length of it will be reduced) and send to A.");
            System.out.println("This key will be used only once by A to send his private_session_key he will use for later message encryption.");           
            
            String sha3hash = Functions.byte2Hex(Cryptor.getSHA3(Cryptor.KeyPublicRestoreFromFile(PUBLIC_KEY_FILE_NAME).getEncoded()));            
            System.out.println("SHA3 hash to send to A["+sha3hash.length()+"]: " + sha3hash);
            //org.bouncycastle.util.encoders.Hex.toHexString(byte [] data)

 
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        PublicKey myPublicKey = null;
        try {            
            //public key can be restored from private directly
            myPublicKey = Cryptor.keyRestorePublicFromPrivate(Cryptor.KeyPrivateRestoreFromFile(PRIVATE_KEY_FILE_NAME));
            System.out.println("Restored Public key if missed: " + Functions.byte2Hex(myPublicKey.getEncoded()));
                                               
            encryptedText = Cryptor.encrypt("SymmetricKeyA", myPublicKey); 
            System.out.println("Encrypted Text Received from Messanger A: " + Functions.byte2Hex(encryptedText));
            
            String plainText = Cryptor.decrypt(encryptedText, Cryptor.KeyPrivateRestoreFromFile(PRIVATE_KEY_FILE_NAME));
            System.out.println("Succesfully Decrypted Text at Messanger B: " + plainText);
            
        } catch (Exception ex) {
            Logger.getLogger(AsymetricEncodeTest.class.getName()).log(Level.SEVERE, null, ex);
        } 
        
        
             

    }
 
}