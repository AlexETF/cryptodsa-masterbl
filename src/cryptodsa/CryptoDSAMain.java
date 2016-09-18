/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptodsa;

import com.oracle.jrockit.jfr.DataType;
import cryptodsa.model.CryptoAES;
import cryptodsa.model.CryptoDSA;
import cryptodsa.model.CryptoUtils;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXBException;

/**
 *
 * @author ZM
 */
public class CryptoDSAMain {

    private static StringBuilder helpText;
    
    static {
        helpText = new StringBuilder();
        helpText.append("Supported commands: " + System.lineSeparator());
        helpText.append("   gendsa [key_length] [path for storing keys]" + System.lineSeparator());
        helpText.append("   sign -in [file path] -key [key path]" + System.lineSeparator());
        helpText.append("   verify -in [xml file path] -key [key path]" + System.lineSeparator());
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        try {
            processCommandLineArgs(args);
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println(ex.getMessage());
        } catch (NoSuchPaddingException ex) {
            System.out.println(ex.getMessage());
        } catch (InvalidKeyException ex) {
            System.out.println(ex.getMessage());
        } catch (IllegalBlockSizeException ex) {
            System.out.println(ex.getMessage());
        } catch (BadPaddingException ex) {
            System.out.println(ex.getMessage());
        }catch (JAXBException ex){
            System.out.println("Invalid file for validation, use generated xml file !");
        }
    }

    private static void processCommandLineArgs(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        if (args.length < 1) {
            System.out.println("See --help for more information");
        } else if (args[0].equals("--help")) {
            displayHelpCommand();
        } else if (args[0].equals("gendsa") && args.length > 1) {
            generateKeysCommand(args);
        } else if (args[0].equals("sign")) {
            signCommand(args);
        } else if (args[0].equals("verify")) {
            verifyCommand(args);
        } else {
            System.out.println("See --help for more information");
        }
    }

    private static void generateKeysCommand(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        int keyLength = 0;
        try {
            keyLength = Integer.parseInt(args[1]);
        } catch (Exception e) {
            System.out.println("Provided parameter is not number. See --help for more information ! ");
            return;
        }
        if (keyLength == 2 || keyLength == 4 || keyLength == 8) {
            if (args.length == 3) {
                new CryptoDSA(args[2]).generateDSAKeys(keyLength);
            } else {
                new CryptoDSA().generateDSAKeys(keyLength);
            }
        } else {
            System.out.println("Length of key parameter must [2, 4, 8] ");
        }
    }

    private static void signCommand(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        CryptoDSA dsa = new CryptoDSA();
        if (args.length == 3 && args[1].equals("-in")) {
            dsa.signFile(args[2], "private.dsa");
        } else if (args.length == 5 && args[1].equals("-in") && args[3].equals("-key")) {
            dsa.signFile(args[2], args[4]);
        } else if (args.length == 5 && args[1].equals("-key") && args[3].equals("-in")) {
            dsa.signFile(args[4], args[2]);
        } else {
            System.out.println("See --help for more information about commands ! ");
            return;
        }
    }

    private static void verifyCommand(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        CryptoDSA dsa = new CryptoDSA();
        boolean verified = false;
        if (args.length == 3 && args[1].equals("-in")){
            verified = dsa.verifySignature(args[2], "public.dsa");
        } else if (args.length == 5 && args[1].equals("-in") && args[3].equals("-key")) {
            verified = dsa.verifySignature(args[2], args[4]);
        } else if (args.length == 5 && args[1].equals("-key") && args[3].equals("-in")) {
            verified = dsa.verifySignature(args[4], args[2]);
        } else {
            System.out.println("See --help for more information about commands ! ");
            return;
        }
        System.out.println("Verification " + ((verified == true) ? "passed" : "failed"));
    }

    private static void displayHelpCommand() {
        System.out.println(helpText);
    }
}
