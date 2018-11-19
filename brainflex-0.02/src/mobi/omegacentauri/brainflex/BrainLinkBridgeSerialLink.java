/**
*
* Copyright (c) 2014 Alexander Pruss
* Distributed under the GNU GPL v3 or later. For full terms see the file COPYING.
*
*/

// serial proxied via BrainLink

package mobi.omegacentauri.brainflex;

import jssc.SerialPort;
import jssc.SerialPortException;

public class BrainLinkBridgeSerialLink extends SerialDataLink {
  // Use information from: http://www.brainlinksystem.com/brainlink-hardware-description
  // and calculator from: http://www.avrcalc.elektronik-projekt.de/xmega/baud_rate_calculator
  // with 32MHz clock rate.
	private static final byte[] BAUD9600 = { '*', 'C', 829>>8, 829&0xFF, -2 };
	private static final byte[] BAUD57600 = { '*', 'C', 0, (byte)135, -2 };
	private static final byte[] BAUD1200 = { '*', 'C', (byte)(6663>>8), (byte)(6663&0xFF), -2 };
	private static final byte[] BAUD19200 = { '*', 'C', (byte)(825>>8), (byte)(825&0xFF), -3 };
	private static final byte[] BAUD115200 = { '*', 'C', 0, (byte)(131&0xFF), -3 };
	private static final byte[] BAUD38400 = { '*', 'C', 0, (byte)(204&0xFF), -2 };

	public BrainLinkBridgeSerialLink(String port) throws Exception {
		super(port);
	}

	@Override
	public void start(int baud) {
		setBaud(baud);
		try {
			p.writeByte((byte)'Z');
		} catch (SerialPortException e) {
		}
	}

	protected void setBaud(int baud) {
		this.baud = baud;
		try {
			if (baud == 9600)
				p.writeBytes(BAUD9600);
			else if (baud == 57600)
				p.writeBytes(BAUD57600);
			else if (baud == 1200)
				p.writeBytes(BAUD1200);
			else if (baud == 19200)
				p.writeBytes(BAUD19200);
			else if (baud == 115200)
				p.writeBytes(BAUD115200);
			else if (baud == 38400)
				p.writeBytes(BAUD38400);
			else {
				System.err.println("Unrecognized baud "+baud);
			}
		}
		catch(SerialPortException e) {
		}
	}

	@Override
	public void preStart(int preBaud, byte[] data) {
		setBaud(preBaud);
		try {
			// Use the standard Brainlink transmit interface
			p.writeBytes(new byte[] { '*', 't', (byte)data.length } );
			p.writeBytes(data);
		} catch (SerialPortException e) {			
		}		
	}
	
	@Override
	public int getFixedBaud() {
		return 0;
	}
}
