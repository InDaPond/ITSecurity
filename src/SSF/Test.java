package SSF;

import RSAKeyCreation.RSAKeyCreation;
import RSAKeyCreation.RSAKeyReader;
import SSF.RSF;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;


/**
 * Created by Philipp Goemann on 06.06.2017.
 */
public class Test {

    public static void main(String args[]) throws Exception {
        String filename = "Name";
        new RSAKeyCreation(filename);

        new SSF(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\TestFileIn",
                System.getProperty("user.dir") + "\\src\\TestFileOut");
        new RSF(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\TestFileOut",
                System.getProperty("user.dir") + "\\src\\files\\Outputfile.pdf"
        );


        //Aufgabe 4
        filename = "TestKey";
        new RSAKeyCreation(filename);
        new SSF(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\files\\ITSAufgabe3.pdf",
                System.getProperty("user.dir") + "\\src\\TestFileOut"
        );
        new RSF(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\TestFileOut",
                System.getProperty("user.dir") + "\\src\\files\\Outputfile.pdf"
        );
    }


}
