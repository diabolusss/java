/*     */ package org.wsocket.ticks;

/*     */ import java.util.concurrent.ConcurrentHashMap;
          import org.java_websocket.WebSocket;
/*     */ 
/*     */ public class Users{
/*  25 */   public static ConcurrentHashMap<String, Users> UserList = new ConcurrentHashMap();
/*     */   public String key;
/*     */   public String hash;
/*     */   public int check;
/*     */   public int id;
/*     */   public String name;
/*     */   public String role;
/*     */   public String type;
/*     */   public WebSocket connector;
/*     */ 
/*     */   public Users(String key, WebSocket connector){
    
/*  70 */     this.check = 0;
/*  71 */     this.hash = "unknown";
/*  72 */     this.key = key;
/*  73 */     this.connector = connector;
/*  74 */     this.id = 0;
/*  75 */     this.name = "Guest";
/*  76 */     this.role = "guest";
/*  77 */     this.type = "demo";
/*     */   }
/*     */ 
/*     */   public static void addNewUser(String key, Users user)
/*     */   {
/*  86 */     if (!UserList.containsKey(key)) {
/*  87 */       UserList.put(key, user);
/*     */     }
/*     */   }
/*     */ 
/*     */   public static void removeUser(String key){
/*  97 */     if (UserList.containsKey(key)){
/*     */       
/*  99 */         Users user = (Users)UserList.get(key);
/* 101 */         UserList.remove(key);
              }


/*     */   }
/*     */ 
/*     */   public static void assignHash(String key, String hash, String name){
/* 117 */     Users user = null;
                
              //if user wih such key exist
/* 118 */     if (UserList.containsKey(key)){
                user = (Users)UserList.get(key);
                user.hash = hash;
                user.name = name;

/*     */     }

/*     */   }
/*     */ 
/*     */   private boolean checkUser(String hash, String type_s) {
/* 144 */     boolean valid = false;
/* 145 */     int id_s = 0;
/* 147 */     String name_s = null;
/* 148 */     String role_s = null;
/* 149 */     String ip_s = null;
/* 150 */     String query = null;
/*     */ 
/* 191 */     String remoteIP = this.connector.getRemoteSocketAddress().getAddress().getHostAddress();
/* 192 */     if ((id_s != 0) && (remoteIP.equals(ip_s))) {
/* 193 */       valid = true;
/*     */ 
/* 196 */       this.hash = hash;
/* 197 */       this.id = id_s;
/* 198 */       this.name = name_s;
/* 199 */       this.role = role_s;
/* 200 */       this.type = type_s;
/*     */     }
/* 204 */     return valid;
/*     */   }
/*     */ 
/*     */   public static Users getUser(String key)
/*     */   {
/* 257 */     if (UserList.containsKey(key)) {
/* 258 */       Users user = (Users)UserList.get(key);
/* 259 */       return user;
/*     */     }
/* 261 */     return null;
/*     */   }
/*     */ }