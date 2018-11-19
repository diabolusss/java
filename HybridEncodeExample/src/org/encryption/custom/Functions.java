/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.encryption.custom;

import custom.Base64;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;

/**
 *
 * @author colt
 */
public class Functions {
    //Made BASE_64_FLAGS public as it's useful to know for compatibility.
    //Encoder flag bit to omit all line terminators (i.e., the output will be on one long line).
    public static final int BASE64_FLAGS = 0;//Base64.NO_WRAP;
    
    
    /**
     * Converts the given bytes into a base64 encoded string suitable for
     * storage.
     *
     * @param salt
     * @return a base 64 encoded salt string suitable to pass into generateKeyFromPassword.
     */
    public static String byte2Base64(byte b[]) throws IOException {
        return Base64.encodeBytes(b, BASE64_FLAGS);
    }
    
    public static byte[] base642Byte(String base) throws IOException {
        return Base64.decode(base, Functions.BASE64_FLAGS);
    }
    
    public static String byte2Hex(byte b[]) {
        java.lang.String hs = "";
        java.lang.String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = java.lang.Integer.toHexString(b[n] & 0xff);
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs.toLowerCase();
    }   
    
    public static byte[] hex2byte(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
 
    public static byte hex2Byte(char a1, char a2) {
        int k;
        if (a1 >= '0' && a1 <= '9') k = a1 - 48;
        else if (a1 >= 'a' && a1 <= 'f') k = (a1 - 97) + 10;
        else if (a1 >= 'A' && a1 <= 'F') k = (a1 - 65) + 10;
        else k = 0;
        k <<= 4;
        if (a2 >= '0' && a2 <= '9') k += a2 - 48;
        else if (a2 >= 'a' && a2 <= 'f') k += (a2 - 97) + 10;
        else if (a2 >= 'A' && a2 <= 'F') k += (a2 - 65) + 10;
        else k += 0;
        return (byte) (k & 0xff);
    }
 
    public static byte[] hex2Byte(String str) {
        int len = str.length();
        if (len % 2 != 0) return null;
        byte r[] = new byte[len / 2];
        int k = 0;
        for (int i = 0; i < str.length() - 1; i += 2) {
            r[k] = hex2Byte(str.charAt(i), str.charAt(i + 1));
            k++;
        }
        return r;
    }
    
    public static byte[] byteConcat(final byte[] a, final byte[] a2) {
        final byte[] result = new byte[a.length + a2.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(a2, 0, result, a.length, a2.length);
        return result;
    }
    
    /**
     * Simple constant-time equality of two byte arrays. Used for security to avoid timing attacks.
     * @param a
     * @param b
     * @return true iff the arrays are exactly equal.
     */
    public static boolean byteArrConstTimeEquality(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    /**
     * Copy the elements from the start to the end
     *
     * @param from  the source
     * @param start the start index to copy
     * @param end   the end index to finish
     * @return the new buffer
     */
    public static byte[] byteCopy(byte[] from, int start, int end) {
        int length = end - start;
        byte[] result = new byte[length];
        System.arraycopy(from, start, result, 0, length);
        return result;
    }
    
    public static void save2File(String filename, String string2save) throws IOException{
        File file = new File(filename);
        //The abstract pathname of the parent directory named by this
        //abstract pathname, or <code>null</code> if this pathname
        //does not name a parent
        
        //mkdirs: Returns:true if and only if the directory was created, along with all 
        //necessary parent directories; false otherwise
        if (file.getParentFile() != null && file.getParentFile().mkdirs()) {
            //Atomically creates a new, empty file named by this abstract 
            //pathname if and only if a file with this name does not yet exist.
            file.createNewFile();
        }        
        
        BufferedWriter pubOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
        pubOut.write(string2save);
        pubOut.flush();
        pubOut.close();
    }
    
    public static byte[] file2Byte(String file) throws IOException {
        BufferedReader pubIn = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        StringBuilder sb = new StringBuilder();
        String tmp;
        do {
            tmp = pubIn.readLine();
            if (tmp != null) sb.append(tmp);
        } while (tmp != null);
        return Functions.hex2Byte(sb.toString());
    }
    
    
}
