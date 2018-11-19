/*
 * When a collision first occurs, send a “Jamming signal” to prevent further 
 *  data being sent. Resend a frame after either 0 seconds or 51.2μs, 
 *  chosen at random. If that fails, resend the frame after 
 *  either 0s, 51.2μs, 102.4μs, or 153.6μs. If that still doesn't work,
 *  resend the frame after k · 51.2μs, where k is a random number between 0 and 2^3 − 1.
 *  In general, after the cth failed attempt, resend the frame after k · 51.2μs, 
 *  where k is a random number between 0 and 2^c − 1.
 */
package org.http;

import org.custom.Functions;

/**
 *
 * @author colt
 */
public class SimpleExpBackoff {    
    static long currbackoffCount = 0; // number of consecutive backoff calls;
    static long sleepIncrement; // amount of time before retry should happen
    static long retryTime; // actual unixtime to compare against when retry is ok.
    
    static long initialSleep;// ms
    static long maxTries;
    
    public SimpleExpBackoff(long initialSleep, long maxTries){
        this.initialSleep = initialSleep;
        this.maxTries = maxTries;
        reset();
    }
    
    /**
    * Reset backoff state. Call this after successful attempts.
    */
    public static void reset() {
        sleepIncrement = initialSleep;
        long cur = System.currentTimeMillis();
        retryTime = cur;
        currbackoffCount = 0;
    }
    
    /**
     * Modify state as if a backoff had just happened. Call this after failed
     * attempts.
     */
    public static void backoff() {
      retryTime = System.currentTimeMillis() + sleepIncrement;
      //sleepIncrement *= 2;
      currbackoffCount++;
      sleepIncrement = initialSleep*Functions.randLong(0, (long)(Math.pow(2,currbackoffCount)-1) ) ;
      
    }
    
    /**
   * Has time progressed enough to do a retry attempt?
   */
  public static boolean isRetryOk() {
    return retryTime <= System.currentTimeMillis() && !isFailed();
  }

  /**
   * Has so much time passed that we assume the failure is irrecoverable?
   * 
   * If this becomes true, it will never return true on isRetryOk, until this
   * has been reset.
   */
  public static boolean isFailed() {
    return currbackoffCount >= maxTries;
  }
  
}
