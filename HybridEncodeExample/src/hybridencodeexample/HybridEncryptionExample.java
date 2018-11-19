package hybridencodeexample;

import org.encryption.asymmetric.RSA;
import org.encryption.hybrid.HybridEncryption;
import org.encryption.custom.Functions;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HybridEncryptionExample {        
    private static String SESSION_PRIVATE_FILENAME = "session_private.key";
    private static String SESSION_PUBLIC_FILENAME = "session_public.key";
    
    public static void main(final String[] args) throws Exception {
        // --- not required for Java 8
        Security.addProvider(new BouncyCastleProvider());

        // --- setup key pair (generated in advance)
        final String passphrase = "owlstead";
        final String originalText = "Текст для отправки";
        
        final KeyPair rsaKeyPair = RSA.keyPairGenerate();
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        System.out.println("++++++++++++++++++++initialRSA++++++++++++++++++++++++++++");
        System.out.println(rsaPublicKey);
        String privatekeyhex = Functions.byte2Hex(rsaPrivateKey.getEncoded());
        System.out.println("HEX representation of raw private key["+privatekeyhex.length()+"]: "+privatekeyhex);
        String privatekeyBase64 = Functions.byte2Base64(rsaPrivateKey.getEncoded());
        System.out.println("BASE64 representation of raw private key["+privatekeyBase64.length()+"]: "+privatekeyBase64);
        
        // --- encode and wrap for safe saving
        byte[] x509EncodedRSAPublicKey = RSA.encodeKey(rsaPublicKey); 
        final byte[] encryptedPrivate = HybridEncryption.encryptRSAAESRand(passphrase, rsaPrivateKey);
        
        String publickeyhex = Functions.byte2Hex(x509EncodedRSAPublicKey);
        System.out.println("HEX representation of public key["+publickeyhex.length()+"]: "+publickeyhex);
        String publickeyBase64 = Functions.byte2Base64(x509EncodedRSAPublicKey);
        System.out.println("BASE64 representation of public key["+publickeyBase64.length()+"]: "+publickeyBase64);
        
        String wrappedprivatekeyhex = Functions.byte2Hex(encryptedPrivate);
        System.out.println("HEX representation of wrapped private key with salt["+wrappedprivatekeyhex.length()+"]: "+wrappedprivatekeyhex);
        String wrappedprivatekeyBase64 = Functions.byte2Base64(encryptedPrivate);
        System.out.println("BASE64 representation of wrapped private key with salt["+wrappedprivatekeyBase64.length()+"]: "+wrappedprivatekeyBase64);
       
        byte[] encryptedText = RSA.encrypt(originalText, rsaPublicKey);
        String encryptedTextHex = Functions.byte2Hex(encryptedText);
        System.out.println("HEX representation of encryptedText["+encryptedTextHex.length()+"]: "+encryptedTextHex);
        String encryptedTextBase64 = Functions.byte2Base64(encryptedText);
        System.out.println("BASE64 representation of encryptedText["+encryptedTextBase64.length()+"]: "+encryptedTextBase64);
        
        //now we can safely save private key
        Functions.save2File(SESSION_PRIVATE_FILENAME, wrappedprivatekeyhex);
        Functions.save2File(SESSION_PUBLIC_FILENAME, publickeyhex);
                
        byte[] privateBytesFromFile = Functions.file2Byte(SESSION_PRIVATE_FILENAME);
        byte[] publicBytesFromFile = Functions.file2Byte(SESSION_PUBLIC_FILENAME);
        
        // --- decode and unwrap
        final RSAPublicKey retrievedRSAPublicKey = RSA.decodePublicKey(publicBytesFromFile);
        final RSAPrivateKey retrievedRSAPrivateKey = HybridEncryption.decryptRSAAESRand(passphrase, privateBytesFromFile);

        // --- check result
        System.out.println("++++++++++++++++++++retrievedRSA++++++++++++++++++++++++++++");
        System.out.println(retrievedRSAPublicKey);
        System.out.println(retrievedRSAPrivateKey);
        
        String decryptedText = RSA.decrypt(Functions.hex2Byte(encryptedTextHex), retrievedRSAPrivateKey);
        System.out.println("decryptedText["+decryptedText.length()+"]: "+decryptedText);
        
    }
}