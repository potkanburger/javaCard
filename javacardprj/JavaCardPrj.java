package javacardprj;

import applets.SmallApplet;
import java.util.Scanner;
import java.util.regex.Pattern;
import javacard.framework.Util;
import javax.smartcardio.ResponseAPDU;

/**
 * @author original: xsvenda, modifications: hu.sebastien
 */
public class JavaCardPrj {
    static CardMngr cardManager = new CardMngr();

    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static byte SELECT_SMALLAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    private final byte selectCM[] = {
        (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xa0, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x18, (byte) 0x43, (byte) 0x4d};
    
    private static byte ERROR[] = {(byte) 0x69, (byte) 0x00};
    private static byte SUCCESS[] = {(byte) 0x90, (byte) 0x00};
    
    private static int NB_SIGNATURE = 3;
    
    public static void main(String[] args) {
        try {            
            if (cardManager.ConnectToCard()) {
                
                // Select our application on card
                cardManager.sendAPDU(SELECT_SMALLAPPLET);
           
                // prepare proper APDU command
                short additionalDataLenPin = 4; //Pin code data has a length of 4 (4 digits, each one is one byte in hexa)
                short additionalDataLen = 1;

                //Building apdu request with Instruction 0x58 to ask for signature
                byte encryptapdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                encryptapdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                encryptapdu[CardMngr.OFFSET_INS] = (byte) 0x50;
                encryptapdu[CardMngr.OFFSET_P1] = (byte) 0x00;
                encryptapdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                encryptapdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
                encryptapdu[CardMngr.OFFSET_DATA] = (byte) 0x44;

                ResponseAPDU response = cardManager.sendAPDU(encryptapdu);                
                
                if(testResponse(response.getBytes(), SUCCESS)){
                    System.out.println("Encryption succesful !");
                }
                
                byte decryptapdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                decryptapdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                decryptapdu[CardMngr.OFFSET_INS] = (byte) 0x50;
                decryptapdu[CardMngr.OFFSET_P1] = (byte) 0x00;
                decryptapdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                decryptapdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
                decryptapdu[CardMngr.OFFSET_DATA] = (byte) 0x44;

                ResponseAPDU response2 = cardManager.sendAPDU(decryptapdu);
                
                if(testResponse(response2.getBytes(), SUCCESS)){
                    System.out.println("Decryption succesful !");
                }
                
                cardManager.DisconnectFromCard();
            
            } else {
                System.out.println("Failed to connect to card");
            }
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
     
    }
    
    /**
     * Method testing if the response matches a specified code
     * @param response from the cardManager
     * @param expect is the code the response is compared too
     * @return true if the response code matches the expected one
     */
    private static boolean testResponse(byte[] response, byte[] expect){
        int lengthR = response.length;
        for(int i= 0;i<2;i++){
            if(response[i+lengthR-2] != expect[i])
                return false;
        }
        return true;
    }
    
}
