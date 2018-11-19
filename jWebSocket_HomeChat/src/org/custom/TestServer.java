package org.custom;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Date;
import org.http.Emailer;

import org.java_websocket.WebSocket;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.wsocket.ticks.Users;
import static org.wsocket.ticks.Users.UserList;


public class TestServer extends WebSocketServer{
	
	/**
	 * Initializator. tries to open <var>port</var> 
	 * @param port
	 * @throws UnknownHostException
	 */
	public TestServer( int port ) throws UnknownHostException {		
		super( new InetSocketAddress( port ) );
	}
	
	/**
	 * Initializator. Creates server using opened port address
	 * @param address
	 */
	public TestServer( InetSocketAddress address ) {
		super( address );
	}

	/**  
	 * Called after an opening handshake has been performed 
	 *  and the given websocket is ready to be written on.
	 *  
	 * @param WebSocket
	 * @param ClientHandshake
	 */
	@Override
	public void onOpen(WebSocket connector, ClientHandshake handshake) {            
            System.out.println( "SERVER:[onOpen] "+ connector.getRemoteSocketAddress().getAddress().toString()+" connected on port " + connector.getRemoteSocketAddress().getPort());   
            connector.send("RDY");
	}

	/**
	 * Callback for string messages received from the remote host
	 * 
	 * @see #onMessage(WebSocket, ByteBuffer)
	 **/
	@Override
	public void onMessage(WebSocket connector, String message) {
        //process raw data        
        System.out.println(message);
		
	}

	/**
	 * Called after the websocket connection has been closed.
	 * 
	 * @param code
	 *            The codes can be looked up here: {@link CloseFrame}
	 * @param reason
	 *            Additional information string
	 * @param remote
	 *            Returns whether or not the closing of the connection was initiated by the remote host.
	 **/
	@Override	
	public void onClose(WebSocket connector, int code, String reason, boolean remote) {
	}
	
	@Override
	public void onFragment( WebSocket conn, Framedata fragment ) {
		System.out.println( 
				"SERVER:[onFragment] Received fragment[" + 
				fragment + "] from "+
				conn
				);
	}

	/**
	 * Called when errors occurs. If an error causes the websocket connection to fail 
	 *  {@link #onClose(WebSocket, int, String, boolean)} will be called additionally.<br>
	 *  This method will be called primarily because of IO or protocol errors.<br>
	 *  If the given exception is an RuntimeException that probably means that you encountered a bug.<br>
	 * 
	 * @param con
	 *            Can be null if there error does not belong to one specific websocket. 
	 *            For example if the servers port could not be bound.
	 **/
	@Override
	public void onError( WebSocket conn, Exception ex ) {
		ex.printStackTrace(System.out);
		if( conn != null ) {
			// some errors like port binding failed may not be assignable to a specific websocket
		}
	}

    

}
