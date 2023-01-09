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

    public static String SUCCESSLOG = "\u001B[32m";
    public static String WARRNINGLOG = "\u001B[33m";
    public static String ERRORLOG = "\u001B[31m";
    public static String RESETCOLORLOG = "\u001B[0m";

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
        GPO();
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
        System.out.println(SUCCESSLOG +"Selecting PSE"+ RESETCOLORLOG);
        r = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PSE,0x00));  
        tlvdecoder(bytesToHex(r.getData()));
        System.out.println(SUCCESSLOG +"Reading PSE record"+ RESETCOLORLOG);
        r = channel.transmit(new CommandAPDU(0x00, 0xB2, 0x01, 0x0C,0x1C));
        List<DecodedData> decoded = tlvdecoder(bytesToHex(r.getData()));
        String AID = decoded.get(0).getChild(0).getChild(0).getDecodedData();
        System.out.println(AID);
        return AID; 
    }
    public static void select_AID(String AID) throws Exception {
      byte[] AIDb = HexFormat.of().parseHex(AID);
       System.out.println(SUCCESSLOG + "Selecting AID:"+AID+ RESETCOLORLOG);
       r = channel.transmit(new CommandAPDU(0x00,0xA4,0x04,0x00,AIDb,0x00)); 
      List<DecodedData> data = tlvdecoder(bytesToHex(r.getData()));

      //check if PDOL exist

      Tag Tag_PDOL = new Tag(HexFormat.of().parseHex("9F38"),true);
      List<DecodedData> PDOL = data.get(0).findAllForTag(Tag_PDOL,data);
      if(PDOL.size() != 0 ){
      String PDOL_value = data.get(0).getChild(1).getChild(2).getChild(0).getDecodedData();
      System.out.println(SUCCESSLOG + "PDOL exist" + RESETCOLORLOG);
      System.out.println(SUCCESSLOG + "PDOL:"+PDOL_value + RESETCOLORLOG);
      }else{
       System.out.println(ERRORLOG + "NO PDOL" + RESETCOLORLOG);
      }
      
    }
    public static void GPO(byte[] PDOL) throws Exception {
     r = channel.transmit(new CommandAPDU(0x80,0xA8,0x00,0x00,PDOL,0x00));
     List<DecodedData> data = tlvdecoder(bytesToHex(r.getData()));
    //  System.out.println(data)

    }

    public static void GPO() throws Exception{
     byte[] PDOL=HexFormat.of().parseHex("8300");
     r = channel.transmit(new CommandAPDU(0x80,0xA8,0x00,0x00,PDOL,0x00));
     List<DecodedData> data = tlvdecoder(bytesToHex(r.getData()));
     System.out.println(data.get(0).getDecodedData());
     String AIP = data.get(0).getDecodedData().substring(0,4);
     String AFL = data.get(0).getDecodedData().substring(4,(data.get(0).getDecodedData().length()-1));
     System.out.println(SUCCESSLOG + "AIP:"+AIP + RESETCOLORLOG);
     System.out.println(SUCCESSLOG + "AFL:"+AFL + RESETCOLORLOG);

    }
}