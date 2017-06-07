package RSAKeyCreation;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyReader {

    private static final String RSA_ALGORITHM = "RSA";



    public RSAKeyReader(){

    }

    private byte[] readKeyToByte(File file) {
        try {
            // die Datei wird geoeffnet und die Daten gelesen
            DataInputStream is = new DataInputStream(new FileInputStream(file));
            // die Laenge des Owners
            int len = is.readInt();
            byte[] ownerName = new byte[len];
            // der Name
            is.read(ownerName);
            // die Laenge des Schluessels
            len = is.readInt();
            // der Schlüssel
            byte[] keyBytes = new byte[len];
            is.read(keyBytes);

            // Datei schliessen
            is.close();
            return keyBytes;
        } catch (IOException e) {
            System.err.println("file not found");
            e.printStackTrace();
        }


        return new byte[0];
    }

    public PublicKey readPublicKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = readKeyToByte(file);
        //Encoding for Public Key
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PublicKey key = keyFactory.generatePublic(pubKeySpec);

        return key;
    }

    public PrivateKey readPrivateKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = readKeyToByte(file);
        //Encoding for Private Key
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PrivateKey key = keyFactory.generatePrivate(privKeySpec);

        return key;
    }
}
