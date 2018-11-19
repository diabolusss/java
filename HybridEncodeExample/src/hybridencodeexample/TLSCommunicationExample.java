package hybridencodeexample;

import org.encryption.symmetric.AESGCMIntegrity;
import org.encryption.asymmetric.RSA;
import org.encryption.custom.CryptorFunctions;
import org.encryption.hybrid.HybridEncryption;
import org.encryption.custom.Functions;
import org.encryption.storage.MACIVCipher;
import org.encryption.storage.SecretKeyPair;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Of course, secure against an active attacker does not mean that the cipher 
 * has no other real-world limitation. For example, most ciphers are safe only 
 * if the user changes the key after too much data have been encrypted. 
 * If you are serious about data encryption, you should study and know those limitations.
 * 
 * 
 * @author colt
 */

public class TLSCommunicationExample {        
    private static String SESSION_SYMETRIC_FILENAME = "session_private2.key";
    private static String SESSION_PRIVATE_FILENAME = "session_private.key";
    private static String SESSION_PUBLIC_FILENAME = "session_public.key";

    public static void main(final String[] args) throws Exception {
        // --- not required for Java 8
        Security.addProvider(new BouncyCastleProvider());

        SecretKeyPair randomKey = AESGCMIntegrity.generateKeyPair();
        String randomKeyString = randomKey.toString();      
        String encryptedMessage = AESGCMIntegrity.encrypt("message", randomKey).toString();
        System.out.println("Store_to_file: "+randomKeyString+":"+encryptedMessage);
        
        SecretKeyPair restoredSessionKey1 = new SecretKeyPair();
        restoredSessionKey1 = restoredSessionKey1.toObject(randomKeyString);
        System.out.println("Restored_from_file: "+AESGCMIntegrity.decrypt2String(new MACIVCipher(encryptedMessage), restoredSessionKey1));
        
        //to provide secure communication we need to share data for symmetric key
        // User A inits secure communication, so he creates asymetric key and shares public key 
        // with user B. User B creates session_key and encrypts its data with received 
        // public key and send to user A. When User A receives session_key data
        // he can use it to decrypt and encrypt messages as User B can.
        // Handshake complete. Session started.
        
        /*
         * Step 1A. User A inits secure session - generates asymetryc session_key
         */
        //generate asymetric session key
        final KeyPair rsaKeyPair = RSA.keyPairGenerate();
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        
        //encode and wrap for safe local storing        
        final byte[] encryptedPrivate = HybridEncryption.encryptRSAAESRand("local_password", rsaPrivateKey);
        byte[] publicKey = RSA.encodeKey(rsaPublicKey);
        
        //save to file
        Functions.save2File(SESSION_PRIVATE_FILENAME, Functions.byte2Hex(encryptedPrivate));
        Functions.save2File(SESSION_PUBLIC_FILENAME, Functions.byte2Hex(publicKey));
        
        System.out.println("STEP 1A. User A sent public key["+Functions.byte2Base64(publicKey).length()+"]: " + Functions.byte2Base64(publicKey));
        
        /*
         * Step 1B. User B receives public key in Base64 - generates symetric session_key 
         */
        //restore public  key
        String receivedPublicKey = Functions.byte2Base64(publicKey);
        final RSAPublicKey retrievedPublicKey = RSA.decodePublicKey(Functions.base642Byte(receivedPublicKey));
        
        //create symetric session_key for message encryption
        //String session_password = Functions.byte2Hex(CryptorFunctions.getRandomBytes(32));
        //byte[] session_salt = AESGCMIntegrity.generateSalt();
        //SecretKeyPair session_key = AESGCMIntegrity.generateKeyPair(session_password, session_salt);
        //generate random key
        SecretKeyPair session_key = AESGCMIntegrity.generateKeyPair();
        
        //encrypt session_key and save session_key to file
        Functions.save2File(SESSION_SYMETRIC_FILENAME+"B", session_key.toString());
        
        //encrypt key with public key and send to user B
        byte[] encryptedText = RSA.encrypt(session_key.toString(), retrievedPublicKey);
        System.out.println("Raw session_key_hex["+session_key.toStringHEX().length()+"]: " + session_key.toStringHEX());
        System.out.println("Raw session_key_base64["+session_key.toString().length()+"]: " + session_key.toString());        
        System.out.println("STEP 1B. User B sent encoded session_key["+Functions.byte2Base64(encryptedText).length()+"]: " + Functions.byte2Base64(encryptedText));
        
        /*
         * Step 2A. User A received encoded session_key - restores key from data - session ready
         */
        String receivedEncodedSessionKey = Functions.byte2Base64(encryptedText);
        String decodedReceivedSessionKey = RSA.decrypt(Functions.base642Byte(receivedEncodedSessionKey), rsaPrivateKey);
        
        //restore session key
        SecretKeyPair restoredSessionKey = new SecretKeyPair();
        restoredSessionKey = restoredSessionKey.toObject(decodedReceivedSessionKey);
        
        //encrypt session_key and save session_key to file
        Functions.save2File(SESSION_SYMETRIC_FILENAME+"A", session_key.toString());
        
        System.out.println("STEP 2A. User A received session_key and saved on local storage. HANDSHAKE COMPLETE. \n SECURE SESSION STARTED");
        
        /*
         * Step XA. User A sends some message to UserB
         */
        //send some encrypted message
        String some_message_fromA_01 = 
            "\nWe, the Fairies, blithe and antic,\n" +
            "Of dimensions not gigantic,\n" +
            "Though the moonshine mostly keep us,\n" +
            "Oft in orchards frisk and peep us. ";
        String encrypted_message = AESGCMIntegrity.encrypt(some_message_fromA_01, restoredSessionKey).toString();
        
        System.out.println("STEP XA. User A sent encoded message["+encrypted_message.length()+"]: " + encrypted_message);
        
        
        /*
         * Step XB. User B received some message from UserA
         */
        String decrypted_message = AESGCMIntegrity.decrypt2String(new MACIVCipher(encrypted_message), session_key);
        System.out.println("STEP XB. User B decoded message["+decrypted_message.length()+"]: " + decrypted_message);
        System.out.println("\tEncryption overhead[x times]:"+(double)encrypted_message.length()/decrypted_message.length());
        
    }
}