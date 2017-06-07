package Test;

import RSAKeyCreation.RSAKeyCreation;
import RSAKeyCreation.RSAKeyReader;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;


/**
 * Created by Philipp Goemann on 06.06.2017.
 */
public class Test {


    public static void main (String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
  //      RSAKeyCreation.createKeyPair("Philipp");
        RSAKeyReader keyReader = new RSAKeyReader();
        PublicKey pubKey = keyReader.readPublicKey(new File("Philipp.pub"));
        PrivateKey prvKey = keyReader.readPrivateKey(new File("Philipp.prv"));
        System.out.println("Pub Key: "+pubKey.toString());
        System.out.println("Priv Key:"+prvKey.toString());

        DataInputStream pubKeyInputStream = new DataInputStream(new FileInputStream("Philipp.pub"));
        int ownerLen = pubKeyInputStream.readInt();
        System.out.println("Laenge: "+ownerLen);
    //    DataOutputStream pubKeyOutputStream = new DataOutputStream(new FileOutputStream("Philipp.pub"));
    //    DataInputStream prvKeyInputStream = new DataInputStream(new FileInputStream("keyOnly.prv"));
    //    DataOutputStream prvKeyOutputStream = new DataOutputStream(new FileOutputStream("Philipp.prv"));

    }


}
