package Test;

import RSAKeyCreation.RSAKeyCreation;
import RSAKeyCreation.RSAKeyReader;
import SSF.RSF;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;


/**
 * Created by Philipp Goemann on 06.06.2017.
 */
public class Test {


    public static void main (String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException {
//        RSAKeyCreation.createKeyPair("Philipp");
        RSAKeyReader keyReader = new RSAKeyReader();
        File publicKeyFile = new File("Philipp.pub");
        File privateKeyFile = new File("Philipp.prv");
        PublicKey pubKey = keyReader.readPublicKey(publicKeyFile);
        PrivateKey prvKey = keyReader.readPrivateKey(privateKeyFile);
        System.out.println("Pub Key: "+pubKey.toString());
        System.out.println("Priv Key:"+prvKey.toString());

        DataInputStream pubKeyInputStream = new DataInputStream(new FileInputStream("Philipp.pub"));
        int ownerLen = pubKeyInputStream.readInt();
        System.out.println("Laenge: "+ownerLen);
    //    DataOutputStream pubKeyOutputStream = new DataOutputStream(new FileOutputStream("Philipp.pub"));
    //    DataInputStream prvKeyInputStream = new DataInputStream(new FileInputStream("keyOnly.prv"));
    //    DataOutputStream prvKeyOutputStream = new DataOutputStream(new FileOutputStream("Philipp.prv"));

        File inputFile = new File("Input.txt");
        File outputFile = new File("Output.ssf");

        String[] ary = null;
        RSF rsf = new RSF("publicKeyFile","privateKeyFile");
        rsf.main(ary);

    }


}
