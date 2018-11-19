package mobi.omegacentauri.brainflex;

import java.awt.SystemColor;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class MindFlexReader {
	static final int PACKET_NO = -1;
	static final int PACKET_MAYBE = 0;
	public static final String[] POWER_NAMES = { "delta", "theta", "low-alpha", "high-alpha", "low-beta", "high-beta",
		"low-gamma", "mid-gamma"
	};
	public List<PowerData> powerData;
	public List<Integer> rawData;
	public long t0;
	int badPacketCount;
	private int lastSignal;
	private PowerData curPowerData;
	private int curRaw;
	private boolean haveRaw;
	private long lastPaintTime;
	public static final int MODE_NORMAL = 0;
	public static final int MODE_RAW = 0x02; // 0x02;
	private BufferedWriter out = null;
    public boolean done;
    // in MODE_RAW, the hardware sends 512 raw packets followed by one processed packet
    // There are ~512 raw packets received per second.
    // I do not know if the sampling times for the raw packets are evenly spaced, or if 
    // it there is a larger gap around the time the processed packet is sent.
    static final int RAW_PER_SECOND = 512; // approximate
    static final int MARKER_CODE = 0x99;
    
    private static final double PROCESSED_PER_SECOND = RAW_PER_SECOND / 512.;

	private DataLink dataLink;
	private BrainFlexGUI gui;
	private int mode;
	private File saveFile;
	private Thread dataReadThread = null;
	private static final String MARKER_RAW = "R";
	private static final String MARKER_POWER = "P";
	static final String MARKER_MARK = "M";

    public MindFlexReader(BrainFlexGUI gui, DataLink dataLink, int mode, File saveFile) {
    	this.mode = mode;
    	this.gui = gui;
    	this.dataLink = dataLink;
    	this.saveFile = saveFile;
		t0 = System.currentTimeMillis();
		powerData = new ArrayList<PowerData>();
		rawData = new ArrayList<Integer>();
		lastSignal = 100;
		badPacketCount = 0;
    }
    

	void readData() throws IOException {
		dataReadThread = Thread.currentThread();
		if (saveFile != null) {
			saveFile.delete();
			saveFile.createNewFile();
			out = new BufferedWriter(new FileWriter(saveFile));
		}
		byte[] buffer = new byte[0];

		gui.log("Connecting");
		if (dataLink.getFixedBaud() == 57600 && mode < MODE_RAW)
			mode = MODE_RAW;
		if (dataLink.getFixedBaud() == 9600)
			mode = MODE_NORMAL;
		
		int baud = 9600;
		System.out.println(""+dataLink.getFixedBaud()+" "+mode+" "+dataLink.getClass().toString());
		if (mode != MODE_NORMAL) {
			dataLink.preStart(9600, new byte[] { (byte)mode });
			if (mode >= MODE_RAW)
				baud = 57600;
			else if (mode == 0x01)
				baud = 1200;
		}
		dataLink.start(baud);

//		dataLink.start(57600);
//		dataLink.transmitFakeBaud(9600, (byte)mode);
		
		// 0x00 : 9600 : normal
		// 0x01 : 1200
		// 0x02 : 57600 : RAW
		// 0x03 : 57600 : lots of 0x82 signals, 4 bytes
		//		sleep(100);
		//dataLink.start(1200);
		//		sleep(100);
		gui.log("Connected");
		
		if (dataLink.isRaw()) {
			t0 = System.currentTimeMillis();
	
			while (!done && !dataLink.eof()) {
				try {
					byte[] data = dataLink.receiveBytes();
					if (data != null) {
						buffer = concat(buffer, data);
		
						int i;
						int n = buffer.length;
						
						for (i = 0; i < n; i++) {
							if (buffer[i] == (byte)0xAA) {
								int length = detectPacket0(buffer, i);
								if (length == PACKET_MAYBE) {
									// possible start of unfinished packet
									byte[] newBuffer = new byte[n - i];
									System.arraycopy(buffer, i, newBuffer, 0, buffer.length - i);
									buffer = newBuffer;
									break;
								}
								else if (length > 0) {
									parsePacket(buffer, i, length);
									i += length - 1;
								}
							}
						}
						
						if (i >= n)
							buffer = new byte[0];
					}
				}
				catch(Exception e) {				
				}
			} 
	
			if (gui != null) {
				gui.updateGraphs();
			}
	
			if (curPowerData != null) {
				gui.log("Received "+rawData.size()+" raw packets over "+curPowerData.t/1000.+" sec: "+(1000.*rawData.size()/curPowerData.t)+"/sec");
				gui.log("Received "+powerData.size()+" processed packets over "+curPowerData.t/1000.+" sec: "+(1000.*powerData.size()/curPowerData.t)+"/sec");
				gui.log("Received "+badPacketCount+" bad packets over "+curPowerData.t/1000.+" sec: "+(1000.*badPacketCount/curPowerData.t)+"/sec");
				System.out.println("Received "+rawData.size()+" raw packets over "+curPowerData.t/1000.+" sec: "+(1000.*rawData.size()/curPowerData.t)+"/sec");
				System.out.println("Received "+powerData.size()+" processed packets over "+curPowerData.t/1000.+" sec: "+(1000.*powerData.size()/curPowerData.t)+"/sec");
				System.out.println("Received "+badPacketCount+" bad packets over "+curPowerData.t/1000.+" sec: "+(1000.*badPacketCount/curPowerData.t)+"/sec");
			}
	
		}
		else {
			t0 = 0;
			String line;
			while (null != (line = dataLink.readLine())) {
				if (line.startsWith(MARKER_MARK)) {
					gui.addMark(line.substring(MARKER_MARK.length()));
				}
				else if (line.startsWith(MARKER_RAW)) {
					rawData.add(Integer.parseInt(line.substring(MARKER_RAW.length())));
				}
				else if (line.startsWith(MARKER_POWER)) {
					powerData.add(new PowerData(line.substring(MARKER_POWER.length())));
				}

				if (gui != null) {
					gui.updateGraphs();
				}
			}
		}
		if (!done) {
			gui.log("End of data");
			while(!done) {
				try {
					Thread.sleep(60000);
				}
				catch(InterruptedException e) {
					break;
				}
			}
		}
		gui.log("Terminated");
		if (dataLink != null) {
			dataLink.stop();
			dataLink = null;
		}
		if (out != null) {
			gui.writeMarks(out);
			out.close();
		}
		if (gui!=null)
			gui.terminate();
	}

	private void parsePacket(byte[] buffer, int pos, int packetLength) {
		curPowerData = new PowerData((int) (System.currentTimeMillis()-t0));
		haveRaw = false;

		//System.out.println("Asked to parse "+pos+" "+packetLength+" of "+buffer.length);
		int end = pos + packetLength - 1;
		pos += 3;

		while((pos = parseRow(buffer, pos, end)) < end);
		
		if (haveRaw) {
			synchronized(rawData) {
				rawData.add(curRaw);
				if (out != null)
					try {
						out.write(MARKER_RAW+curRaw+"\n");
					} catch (IOException e) {
					}
			}
		}

		if (lastSignal < 50 && ( curPowerData.havePower || curPowerData.haveAttention || curPowerData.haveMeditation ) ) {
			synchronized(powerData) {
				if (! dataLink.isRealTime())
					curPowerData.t = (int)(powerData.size() * PROCESSED_PER_SECOND);
				powerData.add(curPowerData);
				if (out != null)
					try {
						out.write(MARKER_POWER+curPowerData.toString()+"\n");
					} catch (IOException e) {
					}
				gui.log("TIME "+curPowerData.t);
			}
		}
		if (dataLink.isRealTime() && System.currentTimeMillis() - lastPaintTime > 250) {
			lastPaintTime = System.currentTimeMillis();
			gui.updateGraphs();
			gui.log("Bad packets: "+badPacketCount);
		}
//		if (System.currentTimeMillis() - t0 > 8000 && mode != -1) {
//			dataLink.transmit(mode);
//			mode = -1;
//		}
	}

	public static void dumpData(byte[] buffer) {
		String out = "";
		for (byte b: buffer) {
			out += String.format("%02X ", 0xFF&(int)b);
		}
		System.out.println(out);
	}	

	private int parseRow(byte[] buffer, int pos, int end) {
//		int excodeLevel = 0;
//		while (pos < end && buffer[pos] == (byte)0x55) {
//			excodeLevel++;
//			pos++;
//		}
		if (pos >= end)
			return end;
		byte code = buffer[pos];
		pos++;
		if (pos >= end)
			return end;
		int dataLength;
		if ((code&(byte)0x80) == (byte)0x00) {
			dataLength = 1;
		}
		else {
			dataLength = 0xFF & (int)buffer[pos];
			pos++;
		}
		if (pos + dataLength > end)
			return end;

//		if (excodeLevel > 0) {
//			gui.log("UNPARSED "+excodeLevel+" "+code);
//			return pos + dataLength;
//		}

		int v;

		switch(code) {
		case (byte)0x02:
			gui.log("POOR_SIGNAL "+(0xFF&(int)buffer[pos]));
		lastSignal = (0xFF)&(int)buffer[pos];
		break;
		case (byte)0x03:
			gui.log("HEART_RATE "+(0xFF&(int)buffer[pos]));
		break;
		case (byte)0x04:
			v = 0xFF&(int)buffer[pos];
		gui.log("ATTENTION "+v);
		curPowerData.attention = v / 100.;
		curPowerData.haveAttention = true;
		break;
		case (byte)0x05:
			v = 0xFF&(int)buffer[pos];
		gui.log("MEDITATION "+v);
		curPowerData.meditation = v / 100.;
		curPowerData.haveMeditation = true;
		break;
		case (byte)0x06:
			gui.log("8BIT_RAW "+(0xFF&(int)buffer[pos]));
		break;
		case (byte)0x07:
			gui.log("RAW_MARKER "+(0xFF&(int)buffer[pos]));
		break;
		case (byte)0x80:
			curRaw = (short)(((0xFF&(int)buffer[pos])<<8) | ((0xFF&(int)buffer[pos+1])));
			haveRaw = true;
//			rtgui.log("RAW " + curData.raw);
		break;
		case (byte)0x81:
			gui.log("EEG_POWER unsupported");
		break;
		case (byte)0x82:
//			rtgui.log("0x82 "+getUnsigned32(buffer,pos));
			curRaw = (short)(((0xFF&(int)buffer[pos+2])<<8) | ((0xFF&(int)buffer[pos+3])));
			haveRaw = true;
		break;
		case (byte)0x83:
			parseASIC_EEG_POWER(buffer, pos);
		break;
		case (byte)0x86:
			gui.log("RRINTERVAL "+(((0xFF&(int)buffer[pos])<<8) | ((0xFF&(int)buffer[pos+1]))) );
		break;
		default:
			gui.log("UNPARSED "/* +excodeLevel+*/+" "+code);
			break;
		}
		
		return pos+dataLength;
	}
	
//	private long getUnsigned32(byte[] buffer, int pos) {
//		return ((0xFF&(long)buffer[pos]) << 24) |
//				((0xFF&(long)buffer[pos+1]) << 16) |
//				((0xFF&(long)buffer[pos+2]) << 8) |
//				((0xFF&(long)buffer[pos+3]));
//	}
//	
//	private int getSigned32(byte[] buffer, int pos) {
//		return ((0xFF&(int)buffer[pos]) << 24) |
//				((0xFF&(int)buffer[pos+1]) << 16) |
//				((0xFF&(int)buffer[pos+2]) << 8) |
//				((0xFF&(int)buffer[pos+3]));
//	}

	private void parseASIC_EEG_POWER(byte[] buffer, int pos) {
		double sum = 0;
		for (int i=0; i<POWER_NAMES.length; i++) {
			int v = getUnsigned24(buffer, pos + 3 * i);
			gui.log(POWER_NAMES[i]+" "+v);
			curPowerData.power[i] = v;
			sum += v;
		}
		for (int i=0; i<POWER_NAMES.length; i++)
			curPowerData.power[i] /= sum;
		curPowerData.havePower = true;
	}

	private static int getUnsigned24(byte[] buffer, int pos) {
		return ((0xFF & (int)buffer[pos+0])<<16) |
				((0xFF & (int)buffer[pos+1])<<8) |
				((0xFF & (int)buffer[pos+2]));
	}

// called only if buffer[i] == 0xAA	
	private int detectPacket0(byte[] buffer, int i) {
//		if (buffer.length <= i)
//			return PACKET_MAYBE;
//		if (buffer[i] != (byte)0xAA)
//			return PACKET_NO;
		if (buffer.length <= i+1)
			return PACKET_MAYBE;
		if (buffer[i+1] != (byte)0xAA)
			return PACKET_NO;
		if (buffer.length <= i+2)
			return PACKET_MAYBE;
		int pLength = 0xFF & (int)buffer[i+2];
		if (pLength > 169) {
			badPacketCount++;
			return PACKET_NO;
		}
		if (buffer.length < i+4+pLength)
			return PACKET_MAYBE;
		
		byte sum = 0;
		for (int j=0; j<pLength; j++)
			sum += buffer[i+3+j];
		if ((sum ^ buffer[i+3+pLength]) != (byte)0xFF) {
			badPacketCount++;
			if (mode < MODE_RAW) 
				gui.log("CSUMERROR "+sum+" vs "+buffer[i+3+pLength]);
			return PACKET_NO;
		}
		return 4+pLength;
	}

	private static byte[] concat(byte[] a, byte[] b) {
		int total = a.length + b.length;
		byte[] out = Arrays.copyOf(a, total);
		System.arraycopy(b, 0, out, a.length, b.length);
		return out;
	}

//	private static void sleep(final int millis)
//	{
//		try
//		{
//			Thread.sleep(millis);
//		}
//		catch (InterruptedException e)
//		{
//		}
//	}
	
	public class PowerData {
		int t;
		double[] power = new double[MindFlexReader.POWER_NAMES.length];
		boolean havePower;
		boolean haveMeditation;
		boolean haveAttention;
		double meditation;
		double attention;
		
		public PowerData(int t) {
			this.t = t;
		}
		
		@Override
		public String toString() {
			String s = ""+t+" "+(havePower?1:0)+" ";
			for (int i = 0 ; i < MindFlexReader.POWER_NAMES.length ; i++)
				s += ""+power[i]+" ";
			return s + (haveMeditation?1:0)+" "+meditation+" "+(haveAttention?1:0)+" "+attention;
		}
		
		public PowerData(String s) {
			System.out.println("Scanning "+s);
			Scanner scan = new Scanner(s);
			t = scan.nextInt();
			havePower = 0 != scan.nextInt();
			for (int i = 0 ; i < MindFlexReader.POWER_NAMES.length ; i++)
				power[i] = scan.nextDouble();
			haveMeditation = 0 != scan.nextInt();
			meditation = scan.nextDouble();
			haveAttention = 0 != scan.nextInt();
			attention = scan.nextDouble();
			scan.close();
		}
	}
	
	public void stop() {
		done = true;
		synchronized(dataLink) {
			if (dataLink != null) {
				dataLink.stop();
				dataLink = null;
			}
		}
		if (dataReadThread != null)
			dataReadThread.interrupt();
	}
}
