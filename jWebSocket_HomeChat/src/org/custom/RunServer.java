package org.custom;

import java.io.IOException;
import java.net.BindException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.http.Emailer;
import org.java_websocket.WebSocketImpl;


public class RunServer {
	static int wsocket_port   = 8880;         
        public static TestServer server;
        private static InetSocketAddress serverSocketAddress=new InetSocketAddress(0);

	public static void main(String[] args) throws IOException, InterruptedException {		
		//debugging mode
		WebSocketImpl.DEBUG = false;

                System.out.println("SERVER:[INIT] Creating server");                
                serverSocketAddress = new InetSocketAddress(wsocket_port);
                server = new TestServer(serverSocketAddress);
                
                
                try{    
                    Socket sock = new Socket();
                    sock.connect(serverSocketAddress, (int)TimeUnit.SECONDS.toMillis(5));
                    sock.close();
                }catch(ConnectException e){
                    Functions.printLog(
                            "SERVER[INIT] ERR "
                            + e.getLocalizedMessage()
                            + " to port " + serverSocketAddress.getPort()+";"
                            +" Restarting wsocket server."
                            );
                    server.stop();
                    server = new TestServer(serverSocketAddress);
                    server.start();
                }		
		Functions.printLog( "SERVER[INIT] INF Server started on port: " + server.getPort());
        }
        
        
                 
}
