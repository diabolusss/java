package hybridencodeexample;

import org.encryption.custom.Functions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESEncryptionEx1 {

        public static final String PROVIDER = "BC";
        public static final int SALT_LENGTH = 20;
        public static final int IV_LENGTH = 16;
        public static final int PBE_ITERATION_COUNT = 100;

        private static final String RANDOM_ALGORITHM = "SHA1PRNG";
        private static final String HASH_ALGORITHM = "SHA-512";
        private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
        private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
        private static final String SECRET_KEY_ALGORITHM = "AES";

        public static  String encrypt(SecretKey secret, String cleartext) throws Exception {
                try {

                        byte[] iv = generateIv();
                        String ivHex = Functions.byte2Hex(iv);
                        IvParameterSpec ivspec = new IvParameterSpec(iv);

                        Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
                        encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
                        byte[] encryptedText = encryptionCipher.doFinal(cleartext.getBytes("UTF-8"));
                        String encryptedHex = Functions.byte2Hex(encryptedText);

                        return ivHex + encryptedHex;

                } catch (Exception e) {
                        throw new Exception("Unable to encrypt", e);
                }
        }

        public static  String decrypt(SecretKey secret, String encrypted) throws Exception {
                try {
                        Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
                        String ivHex = encrypted.substring(0, IV_LENGTH * 2);
                        String encryptedHex = encrypted.substring(IV_LENGTH * 2);
                        IvParameterSpec ivspec = new IvParameterSpec(Functions.hex2Byte(ivHex));
                        decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
                        byte[] decryptedText = decryptionCipher.doFinal(Functions.hex2Byte(encryptedHex));
                        String decrypted = new String(decryptedText, "UTF-8");
                        return decrypted;
                } catch (Exception e) {
                        throw new Exception("Unable to decrypt", e);
                }
        }

        public static  SecretKey getSecretKey(String password, String salt) throws Exception {
                try {
                        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), Functions.hex2Byte(salt), PBE_ITERATION_COUNT, 128);
                        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM, PROVIDER);
                        SecretKey tmp = factory.generateSecret(pbeKeySpec);
                        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
                        return secret;
                } catch (Exception e) {
                        throw new Exception("Unable to get secret key", e);
                }
        }

        public static  String getHash(String password, String salt) throws Exception {
                try {
                        String input = password + salt;
                        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM, PROVIDER);
                        byte[] out = md.digest(input.getBytes("UTF-8"));
                        return Functions.byte2Hex(out);
                } catch (Exception e) {
                        throw new Exception("Unable to get hash", e);
                }
        }

        public static String generateSalt() throws Exception {
                try {
                        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
                        byte[] salt = new byte[SALT_LENGTH];
                        random.nextBytes(salt);
                        String saltHex = Functions.byte2Hex(salt);
                        return saltHex;
                } catch (Exception e) {
                        throw new Exception("Unable to generate salt", e);
                }
        }

        private static  byte[] generateIv() throws NoSuchAlgorithmException, NoSuchProviderException {
                SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
                byte[] iv = new byte[IV_LENGTH];
                random.nextBytes(iv);
                return iv;
        }
        
        public static void main(final String[] args) throws Exception {
            // --- not required for Java 8
            Security.addProvider(new BouncyCastleProvider());
            
            String pass = "@$*FM8sd";
            String salt = generateSalt();

            SecretKey secretKey = getSecretKey(pass, salt);
            
            String msg = encrypt(secretKey,"Secret message");
            System.out.println("EncryptedText:"+msg);
            
            System.out.println("DecryptedText:"+decrypt(secretKey, msg));
        }

}