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

        Select_PSE(pse);
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

    public static List tlvdecoder(String data){

        
        List<DecodedData> decoded = new RootDecoder().decode(data, "EMV", "constructed");
        new DecodedWriter(System.out).write(decoded, "");
        System.out.println("-----------------------------");
        byte[] AID =  HexFormat.of().parseHex("4F");
        //  Tag constructor(val bytes: List<Byte>, val compliant: Boolean = true)
        Tag Aid = new Tag(AID,true);
        // findForTag(tag: Tag, decoded: List<DecodedData>): DecodedD

       System.out.println(decoded.get(0).findForTag(Aid,decoded));
        return decoded;
    }

    public static void Select_PSE(byte[] PSE) throws Exception{
        System.out.print("Selecting PSE and Reading PSE records");
        r = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PSE,0x00));  
        tlvdecoder(bytesToHex(r.getData()));
        r = channel.transmit(new CommandAPDU(0x00, 0xB2, 0x01, 0x0C,0x1C));
        tlvdecoder(bytesToHex(r.getData()));
        // List<DecodedData> Decoded = tlvdecoder(bytesToHex(r.getData()));
        // System.out.println(Decoded.findValueForTag("4F"));

        

    }
}