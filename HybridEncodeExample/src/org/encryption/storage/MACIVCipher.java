package org.encryption.storage;

import org.encryption.custom.Functions;
import java.io.IOException;
import java.util.Arrays;
import org.encryption.custom.CryptorFunctions;
import org.encryption.symmetric.AESCBCIntegrity;

/**
* Holder class that allows us to bundle ciphertext and IV together.
*/
public class MACIVCipher {
    private final String BYTE_ENCODING = 
            "BASE64"
            //"HEX"
            ;
    
   private final byte[] cipherText;
   private final byte[] iv;
   private final byte[] mac;

   public byte[] getCipherText() {
       return cipherText;
   }

   public byte[] getIv() {
       return iv;
   }

   public byte[] getMac() {
       return mac;
   }

   /**
    * Construct a new bundle of ciphertext and IV.
    * @param c The ciphertext
    * @param i The IV
    * @param h The mac
    */
   public MACIVCipher(byte[] c, byte[] i, byte[] h) {
       //cipherText = new byte[c.length];
       //System.arraycopy(c, 0, cipherText, 0, c.length);
       //iv = new byte[i.length];
       //System.arraycopy(i, 0, iv, 0, i.length);
       
       mac          = Functions.byteCopy(h, 0, h.length);
       iv           = Functions.byteCopy(i, 0, i.length);
       cipherText   = Functions.byteCopy(c, 0, c.length);
               //new byte[h.length];
       //System.arraycopy(h, 0, mac, 0, h.length);
   }

   /**
    * Constructs a new bundle of ciphertext and IV from a string of the
    * format <code>base64(iv):base64(ciphertext)</code>.
    *
    * @param base64IvAndCiphertext A string of the format
    *            <code>iv:ciphertext</code> The IV and ciphertext must each
    *            be base64-encoded.
    */
   public MACIVCipher(String encodedString) throws IOException {
       //byte[] stringBytes;
       if(BYTE_ENCODING.equalsIgnoreCase("BASE64")) {
           //stringBytes = Functions.base642Byte(encodedString); 
            String[] civArray = encodedString.split(":");
            if (civArray.length != 3) 
                throw new IllegalArgumentException("Cannot parse iv:ciphertext:mac");
                            
            iv           = Functions.base642Byte(civArray[0]);
            mac          = Functions.base642Byte(civArray[1]);
            cipherText   = Functions.base642Byte(civArray[2]);
                                  
           
       }else if(BYTE_ENCODING.equalsIgnoreCase("HEX")) {
            byte[] stringBytes = Functions.hex2Byte(encodedString);
            
            if(stringBytes.length <= (CryptorFunctions.HMAC_KEY_LENGTH_BITS+AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT)/8 )
                throw new IllegalArgumentException("MACIVCIPHER Length not valid:"+stringBytes.length+"##"+encodedString);
        
            int offset = AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT/8;
            iv           = Functions.byteCopy(stringBytes, 0, offset);

            offset += CryptorFunctions.HMAC_KEY_LENGTH_BITS/8;
            mac          = Functions.byteCopy(stringBytes, iv.length, offset);

            cipherText   = Functions.byteCopy(stringBytes, offset, stringBytes.length);
        
       }else throw new IllegalArgumentException("Wrong Encoding");
       
        /*if(stringBytes.length <= (CryptorFunctions.HMAC_KEY_LENGTH_BITS+AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT)/8 )
                throw new IllegalArgumentException("MACIVCIPHER Length not valid:"+stringBytes.length+"##"+encodedString);
        
        int offset = AESCBCIntegrity.SECRETKEY_DERIVATION_SIZE_BIT/8;
        iv           = Functions.byteCopy(stringBytes, 0, offset);

        offset += CryptorFunctions.HMAC_KEY_LENGTH_BITS/8;
        mac          = Functions.byteCopy(stringBytes, iv.length, offset);

        cipherText   = Functions.byteCopy(stringBytes, offset, stringBytes.length);*/;
   }
   
   /**
    * Encodes this ciphertext, IV, mac as a string.
    *
    * @return base64(iv) : base64(mac) : base64(ciphertext).
    * The iv and mac go first because they're fixed length.
    */
   @Override
   public String toString() {
       if(BYTE_ENCODING.equalsIgnoreCase("HEX")) 
            return toStringHEX();
        
        else if(BYTE_ENCODING.equalsIgnoreCase("BASE64")) 
            return toStringBASE64();
        
        else 
            return null;
   }
   
   public String toStringBASE64() {
       try {
           //return Functions.byte2Base64(iv) + Functions.byte2Base64(mac) + Functions.byte2Base64(cipherText);
           return Functions.byte2Base64(iv) + ":" + Functions.byte2Base64(mac) + ":" + Functions.byte2Base64(cipherText);
           
       } catch (IOException ex) {
           System.out.println(ex);
       }
       return null;
   }
   
   public String toStringHEX() {
        return Functions.byte2Hex(iv)+Functions.byte2Hex(mac)+Functions.byte2Hex(cipherText);
   }

   @Override
   public int hashCode() {
       final int prime = 31;
       int result = 1;
       result = prime * result + Arrays.hashCode(cipherText);
       result = prime * result + Arrays.hashCode(iv);
       result = prime * result + Arrays.hashCode(mac);
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
       MACIVCipher other = (MACIVCipher) obj;
       
       if(Functions.byteArrConstTimeEquality(cipherText, other.cipherText))        
       //if (!Arrays.equals(cipherText, other.cipherText))
           return false;
       if(Functions.byteArrConstTimeEquality(iv, other.iv))   
       //if (!Arrays.equals(iv, other.iv))
           return false;
       if(Functions.byteArrConstTimeEquality(mac, other.mac))   
       //if (!Arrays.equals(mac, other.mac))
           return false;
       return true;
   }
}
