package RSAKeyCreation;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyCreation {
    private final static int KEY_SIZE = 2048;
    private final static String KEY_ALGORITHM = "RSA";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        if (args.length != 1)
            throw new IllegalArgumentException();

        RSAKeyCreation.createKeyPair(args[0]);

        System.out.println("Schluessel wurden erzeugt fuer " + args[0]);

    }

    public static void createKeyPair(String owner) throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        generator.initialize(KEY_SIZE);
        KeyPair keyPair = generator.generateKeyPair();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        File publicKeyFile = new File(owner + ".pub");
        File keyOnly = new File("keyOnly.pub");
        DataOutputStream pubKeyOutputStream = new DataOutputStream(new FileOutputStream(publicKeyFile));
        pubKeyOutputStream.writeInt(owner.getBytes().length);
        pubKeyOutputStream.write(owner.getBytes());
        pubKeyOutputStream.writeInt(publicKeyBytes.length);
        pubKeyOutputStream.write(publicKeyBytes);
        pubKeyOutputStream.flush();
        pubKeyOutputStream.close();
        pubKeyOutputStream = new DataOutputStream(new FileOutputStream(keyOnly));
        pubKeyOutputStream.write(publicKeyBytes);
        pubKeyOutputStream.flush();
        pubKeyOutputStream.close();

        File privateKeyFile = new File(owner + ".prv");
        keyOnly = new File("keyOnly.prv");
        DataOutputStream privateKeyOutputStream = new DataOutputStream(new FileOutputStream(privateKeyFile));
        privateKeyOutputStream.writeInt(owner.getBytes().length);
        privateKeyOutputStream.write(owner.getBytes());
        privateKeyOutputStream.writeInt(privateKeyBytes.length);
        privateKeyOutputStream.write(privateKeyBytes);
        privateKeyOutputStream.flush();
        privateKeyOutputStream.close();
        pubKeyOutputStream = new DataOutputStream(new FileOutputStream(keyOnly));
        pubKeyOutputStream.write(privateKeyBytes);
        pubKeyOutputStream.flush();
        pubKeyOutputStream.close();
    }

}
