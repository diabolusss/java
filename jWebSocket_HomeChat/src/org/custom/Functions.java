/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.custom;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Calendar;
import java.util.Random;

/**
 *
 * @author colt
 */
public class Functions {
    /**
    * Outputs message with timestamp
    * @param msg 
    */
    public static void printLog(String msg){
       System.out.println( "<" + Calendar.getInstance().getTime().toString() + "> " + msg);
    }
    
    /**
     * Generate pseudo random integers in diapason[min,max]
     * @param min
     * @param max
     * @return 
     * @see java.util.Random#nextInt(int)
     */
    public static int randInt(int min, int max) {

        // Usually this can be a field rather than a method variable
        Random rand = new Random();

        // nextInt is normally exclusive of the top value,
        // so add 1 to make it inclusive
        int randomNum = (int) (rand.nextInt((max - min) + 1)) + min;

        return randomNum;
    }
    
   /**
    * Returns a psuedo-random number between min and max, inclusive.
    * The difference between min and max can be at most
    * <code>Integer.MAX_VALUE - 1</code>.
    *
    * @param min Minimim value
    * @param max Maximim value.  Must be greater than min.
    * @return Integer between min and max, inclusive.
    * @see java.util.Random#nextDouble()
    */
   public static long randLong(long min, long max) {

       // Usually this can be a field rather than a method variable
       Random rand = new Random();

       // nextInt is normally exclusive of the top value,
       // so add 1 to make it inclusive
       long randomNum = (long) (rand.nextDouble()*((max - min) + 1)) + min;

       return randomNum;
   }
   
   //deprecated
    public static int generateRandom(int n) {
        Random random = new Random();

        if (n == 1) {   
            if (generateRandom(50) > 50) {
                return 1;
            }
            return 0;
        }
        return Math.abs(random.nextInt()) % n;
    }
   
   /**
     * Parses external ip from websites
     * @return string
     *              if ok
     *          null
     *              is smth went wrong
     */
    public static String getExternalIp() {
        String IP_GETTER1_URL = "http://api.externalip.net/ip";
        String IP_GETTER2_URL = "http://checkip.amazonaws.com/";
        
        BufferedReader reader = null;
        String line = "";
        int tries = 0;
        do {	
            try {
                    reader = new BufferedReader(new InputStreamReader(new URL(IP_GETTER1_URL).openStream()));
                    line = reader.readLine();
                    
            } catch (FileNotFoundException fne) {
                    System.out.println("File not found for url: " + IP_GETTER1_URL);
                    return null;
                    
            } catch (IOException ioe) {
                    System.out.println("Got IO Exception, tries = " + (tries + 1));
                    System.out.println("Message: " + ioe.getMessage());
                    tries++;
                    try {
                            Thread.currentThread().sleep(300000);
                    } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                    }
                    continue;
                    
            } catch (Exception exc) {
                    exc.printStackTrace(System.out);
            }
        } while (reader == null && tries < 5);

        if (line != null && line.length() > 0) {
                System.out.println("Your external ip address is: " + line);
        }
        else {
                System.out.println("Sorry, couldn't get your ip address");
        }

        return line;
    }

}
