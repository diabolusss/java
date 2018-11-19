/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.custom.Functions;

/**
 *
 * @author colt
 */
public class HTTPURLConnection {    
    public static final int DEFAULT_QUOTA = 1000000;
    
    public static final String USER_AGENT = "hodiko.v@inbox.lv";
    public static final String SERVICE_PROVIDER_URL = "-http://www.random.org/integers/";
    public static final String SERVICE_PROVIDER_QUOTA_URL = "http://www.random.org/quota/";
    
    public static long availableQuota = 0;
    
    private static  int randomNumberListSize;
    public static  int minRandomNumber;
    public static  int maxRandomNumber;
    
    private static SimpleExpBackoff backoff;// = new SimpleExpBackoff(1, 50);
    public static List<Integer> receivedNums = new ArrayList<Integer>();
    
    //init
    public HTTPURLConnection(long initSleep, long tries, int listSize, int min, int max){
        this.backoff = new SimpleExpBackoff(initSleep, tries);
        this.randomNumberListSize = listSize;
        this.minRandomNumber = min;
        this.maxRandomNumber = max;
    }    
    
    /**
     * Tries to connect to service provider and get generated number
     * @param listSize
     *          number of random integers
     * @param min 
     *          minimal border
     * @param max
     *          max border
     * 
     * @return randomNum list
     *          null if smth went wrong 
     */    
    public static List<Integer> getRandomIntList(int listSize, int min, int max) {
        URL _url = null;
        HttpURLConnection con = null;
        int responseCode;

        try {
            _url = new URL(SERVICE_PROVIDER_URL+"?num="+listSize+"&min="+min+"&max="+max+"&col="+listSize+"&base=10&format=plain&rnd=new");
            con = (HttpURLConnection) _url.openConnection();
            
            // optional default is GET
            con.setRequestMethod("GET");
            
            //add request header
            con.setRequestProperty("User-Agent", USER_AGENT);
            
            responseCode = con.getResponseCode();

        } catch (IOException ex) {
            System.out.println("HTTPURLConnection:[GETRANDOMORGINT] ERROR " + ex.getLocalizedMessage());
            return new ArrayList<Integer>();
        }
        
        //System.out.println("\nSending 'GET' request to URL : " + url);
        //System.out.println("Response Code : " + responseCode);
        switch(responseCode){
            case 200: //OK
                break;
            case 301:
            case 503: System.out.println("HTTPURLConnection:[GETRANDOMORGINT] Status Code 503\\301 Service Unavailable");
                return new ArrayList<Integer>();
        }
        
        StringBuffer response = null;
        
        List<String> items;        
        
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            
            response = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
            }
            
            //print result
            //System.out.println(response.toString());
            items = Arrays.asList(response.toString().split("\\s*\t\\s*"));
            //System.out.println(items.toString());
            
        } catch (IOException ex) {
            System.out.println("HTTPURLConnection:[GETRANDOMORGINT] ERROR " + ex.getLocalizedMessage());
            return new ArrayList<Integer>();
        }
        
        List<Integer> randomNums = new ArrayList<Integer>();        
        for(int i = 0; i < items.size(); i++){
            try{
                randomNums.add(Integer.parseInt(items.get(i)));

            }catch(NumberFormatException ex){
                System.out.println("HTTPURLConnection:[GETRANDOMORGINT] ERROR " + ex.getLocalizedMessage());

            }
        }
        
        if(randomNums.size() > 0) return randomNums;
        else return new ArrayList<Integer>();
    }
    
    /**
     * Get available quota for this ip from service provider
     * @return quota
     *              -1 if failed
     */
    public static int getQuota(){
        URL _url = null;
        HttpURLConnection con = null;
        int responseCode;

        try {
            _url = new URL(SERVICE_PROVIDER_QUOTA_URL+"?format=plain");
            con = (HttpURLConnection) _url.openConnection();
            
            // optional default is GET
            con.setRequestMethod("GET");
            
            //add request header
            con.setRequestProperty("User-Agent", USER_AGENT);
            
            responseCode = con.getResponseCode();

        } catch (IOException ex) {
            System.out.println("HTTPURLConnection:[GETQUOTA] ERROR " + ex.getLocalizedMessage());
            return -1;
        }
        
        //System.out.println("\nSending 'GET' request to URL : " + url);
        //System.out.println("Response Code : " + responseCode);
        switch(responseCode){
            case 200: //OK
                break;
            case 301:
            case 503: System.out.println("HTTPURLConnection:[GETRANDOMORGINT] Status Code 503\\301 Service Unavailable");
                return -1;
        }
        
        StringBuffer response = null;
        
        try  {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            
            response = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
            }
            
        } catch (IOException ex) {
            System.out.println("HTTPURLConnection:[GETQUOTA] ERROR " + ex.getLocalizedMessage());
            return -1;
        }
        
        int randomNum = -1;
        
        try{
            randomNum = Integer.parseInt(response.toString());

        }catch(NumberFormatException ex){
            System.out.println("HTTPURLConnection:[GETQUOTA] ERROR " + ex.getLocalizedMessage());

        }   
        
        return randomNum;
    }
    
    /**
     * Implements exponential back off if server is unavailable or max quota exceeds
     * otherwise gets set of random numbers
     * @return true
     *              if succeed otherwise false
     * 
     */
    public static boolean communicate2RandomOrg(){        
        long quota = -1;
        
        //if not exceeded max attempt number
        if(backoff.isFailed()){
            System.out.println("HTTPURLConnection:[comm2RandOrg] ERROR EXCEEDED MAX TRIES COUNT[" + backoff.maxTries + "]");
            return false;
        }
            
        //if previously failed to get quota or its negative and now is possible to make another retry
        if(backoff.isRetryOk() && quota < 0){                
            quota = getQuota();

            //if quota negative 
            if(quota < 0){
                backoff.backoff();
                System.out.printf("HTTPURLConnection:[comm2RandOrg] ERROR Server not available or quota[%d] negative\n", quota);
                return false;
            }
            System.out.printf("HTTPURLConnection:[comm2RandOrg] quota[%d]\n", quota);
                
            availableQuota = quota;

            receivedNums = getRandomIntList(randomNumberListSize, minRandomNumber, maxRandomNumber);
            
            if(!receivedNums.isEmpty()){
                backoff.reset();
                System.out.printf("HTTPURLConnection:[comm2RandOrg] INFO Received positive quota[%d]. Received random numbers. Resetting backoff counter.\n", quota);
                return true;

            }else{
                backoff.backoff();
                System.out.println("HTTPURLConnection:[comm2RandOrg] ERROR Failed to get number list from server");
                return false;
            }

        }
        return false;
    }    
    
    /**
     * If server is not available generate numbers at your own
     * @return 
     */
    //public static List<Integer> generateRandomNumberList(){
    public static void generateRandomNumberList(){
        List<Integer> randomList = new ArrayList<Integer>();
        
        for(int i = 0; i < randomNumberListSize; i++){
            randomList.add(Functions.randInt(minRandomNumber, maxRandomNumber));
        }
        receivedNums = randomList;
        //return randomList;
    }  
    
}
