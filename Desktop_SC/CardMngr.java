package simpleapdu;

import java.util.EnumSet;
import java.util.List;

import pro.javacard.gp.GlobalPlatform;
import pro.javacard.gp.SessionKeyProvider;
import pro.javacard.gp.PlaintextKeys;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPKeySet.Diversification;
import pro.javacard.gp.GlobalPlatform.APDUMode;
import pro.javacard.gp.GlobalPlatform.ExtendedMode;
import pro.javacard.gp.AID;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardChannel;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class CardMngr {
    private byte APPLET_AID[] = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C, 
    (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    public static final byte OFFSET_CLA = 0x00;
    public static final byte OFFSET_INS = 0x01;
    public static final byte OFFSET_P1 = 0x02;
    public static final byte OFFSET_P2 = 0x03;
    public static final byte OFFSET_LC = 0x04;
    public static final byte OFFSET_DATA = 0x05;
    public static final byte HEADER_LENGTH = 0x05;
    public final static short DATA_RECORD_LENGTH = (short) 0x80; // 128B per record
    public final static short NUMBER_OF_RECORDS = (short) 0x0a; // 10 records
    
    private CardTerminal m_terminal = null;
    private CardChannel m_channel = null;
    private Card m_card = null;
    
    public boolean ConnectToCard() throws Exception {
        List terminalList = GetReaderList();

        if (terminalList.isEmpty()) {
            System.out.println("No terminals found");
            return false;
        }

        boolean cardin = false;
        for (int i = 0; i < terminalList.size(); i++) {
            m_terminal = (CardTerminal) terminalList.get(i);
            if (m_terminal.isCardPresent()) {
                m_card = m_terminal.connect("*");
                m_channel = m_card.getBasicChannel();
                cardin = true;
            }
        }
            
        return cardin;
    }

    public void DisconnectFromCard() throws Exception {
        if (m_card != null) {
            m_card.disconnect(false);
            m_card = null;
        }
    }
    
    public List GetReaderList() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List readersList = factory.terminals().list();
            return readersList;
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
            return null;
        }
    }

    public ResponseAPDU sendAPDU(byte apdu[]) throws Exception {
        final SessionKeyProvider keys;
        GlobalPlatform gp = new GlobalPlatform(m_card.getBasicChannel());
        CommandAPDU commandAPDU = new CommandAPDU(apdu);
        
        gp.select(null);
        gp.select(new AID(APPLET_AID));
        
        EnumSet<APDUMode> mode = GlobalPlatform.defaultMode.clone();
        EnumSet<ExtendedMode> extMode = GlobalPlatform.defaultExtMode.clone();
        extMode.add(ExtendedMode.extDEC);
        
        if (apdu[OFFSET_LC] > 0) {
            mode.add(APDUMode.ENC);
        }
        
        keys = PlaintextKeys.fromMasterKey(GPData.defaultKey, Diversification.NONE);

        gp.openSecureChannel(keys, null, 0, mode, extMode);
        ResponseAPDU responseAPDU = gp.transmit(commandAPDU);
        
        return responseAPDU;
    }

    public static String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }

    public static char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }

    public static String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append("");
        }
        return (buf.toString());
    }
    
    
    static String bytesToHex(ResponseAPDU response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        
        return bytesToHex(response.getData());
    }
}
