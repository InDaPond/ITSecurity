package RSAKeyCreation;

import java.io.*;
import java.security.*;

public class RSAKeyCreation {
    private final static int KEY_SIZE = 2048;
    private final static String KEY_ALGORITHM = "RSA";

   // public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
//        if (args.length != 1)
//            throw new IllegalArgumentException();
//
//        RSAKeyCreation.createKeyPair(args[0]);
//
//        System.out.println("Schluessel wurden erzeugt fuer " + args[0]);
//
//    }

        public static void main(String args[]){
            if(args.length != 1) {
                System.out.println("Usage: RSAKeyCreation <Wanted name for the key files>");
            }

            String filename = args[0];
            new RSAKeyCreation(filename);
        }

        private File publicKey;
        private File privateKey;

    public RSAKeyCreation(String name){
            this.publicKey = new File(System.getProperty("user.dir")+ "\\src\\" + name + ".pub");
            this.privateKey = new File(System.getProperty("user.dir")+ "\\src\\" + name + ".prv");

            Key pub = null;
            Key priv = null;

            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                SecureRandom random = new SecureRandom();
                keyGen.initialize(2048, random);
                KeyPair kp = keyGen.generateKeyPair();
                pub = kp.getPublic();
                priv = kp.getPrivate();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            createKeyFile(name,pub, ".pub");
            createKeyFile(name,priv,".prv");
        }


        private void createKeyFile(String name, Key key, String ending) {
            // OutputStream to write to File
            FileOutputStream outputStream = null;
            File file = new File(System.getProperty("user.dir")+ "\\src\\" + name + ending);
            try {
                outputStream = new FileOutputStream(file);
                DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
                // Length of user name
                dataOutputStream.writeInt(name.length());
                // Name
                dataOutputStream.write(name.getBytes(),0,name.length());
                // Length of public key
                dataOutputStream.writeInt(key.getEncoded().length);
                // PublicKey
                dataOutputStream.write(key.getEncoded(),0,key.getEncoded().length);
                dataOutputStream.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

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
