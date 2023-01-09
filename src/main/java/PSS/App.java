package PSS;

import java.security.Security;
import java.security.NoSuchAlgorithmException;
import javax.smartcardio.*;
import PSS.jnasmartcardio.Smartcardio;
import java.util.*;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import java.util.*;
import io.github.binaryfoo.decoders.Decoders;
import io.github.binaryfoo.*;
import io.github.binaryfoo.cmdline.*;
import java.util.*;
import io.github.binaryfoo.tlv.Tag;

public class App{

    public static CardChannel channel;
    public static TerminalFactory context;
    public static CardTerminals terminals;
    public static ResponseAPDU r;

    public static void main(String args[]) throws Exception {

        

        if (true) {
            Security.addProvider(new Smartcardio());
            context = TerminalFactory.getInstance("PC/SC", null, Smartcardio.PROVIDER_NAME);
            terminals = context.terminals();
        } else {
            TerminalFactory terminalFactory = TerminalFactory.getDefault();
            terminals = terminalFactory.terminals();
        }

        // TerminalFactory context = TerminalFactory.getDefault();
        List<CardTerminal> terminalList = context.terminals().list();

        // Use the first card reader:
        CardTerminal terminal = terminalList.get(0);

        System.out.println("Card Terminal" + terminalList.size());

        // Establish a connection with the card:
        Card card = terminal.connect("*");
        System.out.println("Card: " + card);

        channel = card.getBasicChannel();
        // channel = card.openLogicalChannel();
        byte[] pse =  HexFormat.of().parseHex("315041592E5359532E4444463031");//00 A4 04 00 315041592E5359532E4444463031
        
        String AID = Select_PSE(pse);
        select_AID(AID);
        card.disconnect(false);

       

        while(true){
            terminals.waitForChange();
        }

        // card.disconnect(false);
    }

    public static String GenerateRandomHex(){

        Random r = new Random();
        int n = r.nextInt();
        String Hexadecimal = Integer.toHexString(n);
        return Hexadecimal;
    }

    public static String bytesToHex(byte[] bytes) {

        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static void runAPDU(byte[] apdu) throws CardException {

        ResponseAPDU r = channel.transmit(new CommandAPDU(apdu));
        // System.out.println("Row byte:" + bytesToHex(r.getBytes()));
        // System.out.println("SW:" + r.toString());
        // System.out.println("Data:" + bytesToHex(r.getData()));
        tlvdecoder(r.toString());
    }

    public static void runAPDU(int CLA, int INS, int P1, int P2/*, byte Lc*/, int Le) throws CardException{

        ResponseAPDU r = channel.transmit(new CommandAPDU(CLA, INS, P1, P2, Le));

        // System.out.println("Row byte:" + bytesToHex(r.getBytes()));
        // System.out.println("SW:" + r.toString());
        // System.out.println("Data:" + bytesToHex(r.getData()));

        tlvdecoder(r.toString());
    }

    public static void runAPDU(int CLA, int INS, int P1, int P2/*, byte Lc*/, byte[] DataField, int Le)throws CardException{
        // ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00,b, 0x00));

        ResponseAPDU r = channel.transmit(new CommandAPDU(CLA, INS, P1, P2, DataField, Le));

        // System.out.println("Row byte:" + bytesToHex(r.getBytes()));
        // System.out.println("SW:" + r.toString());
        // System.out.println("Data:" + bytesToHex(r.getData()));
        
    }

    public static List<DecodedData> tlvdecoder(String data){

        
        List<DecodedData> decoded = new RootDecoder().decode(data, "EMV", "constructed");
        new DecodedWriter(System.out).write(decoded, "");
        return decoded;
    }

    public static String Select_PSE(byte[] PSE) throws Exception{
        System.out.println("\u001B[33m"+"Selecting PSE"+ "\u001B[0m");
        r = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PSE,0x00));  
        tlvdecoder(bytesToHex(r.getData()));
        System.out.println("\u001B[33m"+"Reading PSE record"+ "\u001B[0m");
        r = channel.transmit(new CommandAPDU(0x00, 0xB2, 0x01, 0x0C,0x1C));
        List<DecodedData> decoded = tlvdecoder(bytesToHex(r.getData()));
        String AID = decoded.get(0).getChild(0).getDecodedData();
        String AIDLength = AID.substring(2,4);
        AID = AID.substring(4,18);
        System.out.println("AID-Length:"+AIDLength);
        System.out.println("AID:"+AID);
        return AID; 
    }
    public static void select_AID(String AID) throws Exception {
      byte[] AIDb = HexFormat.of().parseHex(AID);
       System.out.println("\u001B[33m" + "Selecting AID:"+AID+ "\u001B[0m");
       r = channel.transmit(new CommandAPDU(0x00,0xA4,0x04,0x00,AIDb,0x00)); 
        tlvdecoder(bytesToHex(r.getData()));


    }
}