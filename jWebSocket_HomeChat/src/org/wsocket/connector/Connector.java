/*    */ package org.wsocket.connector;
/*    */ 
/*    */ import java.nio.channels.SocketChannel;
/*    */ 
/*    */ public class Connector
/*    */ {
/* 11 */   private SocketChannel theSocketChannel = null;
/* 12 */   private String key = null;
/* 13 */   private String authKey = null;
/*    */ 
/*    */   public Connector(SocketChannel socketChannel, String setKey)
/*    */   {
/* 22 */     this.key = (setKey + "_" + System.currentTimeMillis());
/* 23 */     this.theSocketChannel = socketChannel;
/*    */   }
/*    */ 
/*    */   public SocketChannel getSocketChannel()
/*    */   {
/* 31 */     return this.theSocketChannel;
/*    */   }
/*    */ 
/*    */   public String getKey()
/*    */   {
/* 39 */     return this.key;
/*    */   }
/*    */ 
/*    */   public String getAuthKey()
/*    */   {
/* 47 */     return this.authKey;
/*    */   }
/*    */ 
/*    */   public void setAuthKey(String authKey)
/*    */   {
/* 55 */     this.authKey = authKey;
/*    */   }
/*    */ }

/* Location:           C:\Users\grigory\Documents\vkurse.com\websocket\WebSocket_Server_demo_dukascopy2.jar
 * Qualified Name:     org.wsocket.connector.Connector
 * JD-Core Version:    0.6.2
 */