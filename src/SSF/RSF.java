package SSF;

import RSAKeyCreation.RSAKeyReader;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by alena on 07.06.2017.
 */
public class RSF {

    private static PublicKey publicRSAKey;
    private static PrivateKey privateRSAKey;
    private String publicRSAFile;
    private String privateRSAFile;

    public RSF(String publicRSAFile, String privateRSAFile) {
        this.publicRSAFile = publicRSAFile;
        this.privateRSAFile = privateRSAFile;
    }

    public static void main(String args[]) throws InvalidKeySpecException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        RSF rsf = new RSF("Philipp.pub", "Philipp.prv");
        RSAKeyReader keyReader = new RSAKeyReader();
        PrivateKey privateKey = keyReader.readPrivateKey(new File(rsf.getPrivateRSAFile()));
        rsf.setPrivateKey(privateKey);
        PublicKey publicKey = keyReader.readPublicKey(new File(rsf.getPublicRSAFile()));
        rsf.setPublicKey(publicKey);

        rsf.readAndVerifySecureFile(new File("Output.ssf"));
    }

    private byte[] readAndVerifySecureFile(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        byte[] encryptedSecretKey = null;
        byte[] signatureBytes = null;
        byte[] pubKeyBytes = null;
        byte[] parameterBytes = null;
        byte[] encryptedData = null;

        DataInputStream inputStream = new DataInputStream(new FileInputStream(file));

        int secretKeyLength = inputStream.readInt();
        System.out.println("Laenge secretkey:" + secretKeyLength);
        encryptedSecretKey = new byte[secretKeyLength];

        inputStream.read(encryptedSecretKey);
        System.out.println("encryptedSecretKey: " + new String(encryptedSecretKey));


        // die Laenge der Signatur
        int signatureLength = inputStream.readInt();
        System.out.println("Laenge Signatur: " + signatureLength);
        signatureBytes = new byte[signatureLength];

        inputStream.read(signatureBytes);
        System.out.println("Signatur in Bytes : " + new String(signatureBytes));


        // die Laenge der alg. Parameter
        int parameterLength = inputStream.readInt();
        System.out.println("Laenge alg Params: " + parameterLength);
        parameterBytes = new byte[parameterLength];

        inputStream.read(parameterBytes);
        System.out.println("Parameter in Bytes : " + new String(parameterBytes));


        encryptedData = new byte[(int) file.length()];

        inputStream.read(encryptedData);
        System.out.println("Encrypted Data: " + new String(encryptedData));


        inputStream.close();

        byte[] decData = decrypt(encryptedSecretKey, privateRSAKey, parameterBytes, encryptedData);

        return decData;

    }

    public byte[] decrypt(byte[] secretKeyBytes, Key key, byte[] parameterBytes, byte[] encryptedDataBytes) throws NoSuchAlgorithmException,
            IOException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] rsaEncData = cipher.update(secretKeyBytes);

        byte[] decRest = cipher.doFinal();

        byte[] allSecretKeyDecDataBytes = concatenate(rsaEncData,decRest);

        System.out.println("Ergebnis:" + new String(allSecretKeyDecDataBytes) + allSecretKeyDecDataBytes.length);

        SecretKeySpec skspec = new SecretKeySpec(allSecretKeyDecDataBytes, "AES");
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Algorithmische Parameter aus Parameterbytes ermitteln (z.B. IV)TODO: können wir nicht
        AlgorithmParameters algorithmParms = AlgorithmParameters
                .getInstance("AES");
        algorithmParms.init(parameterBytes);

        System.out.println("hier stirbt er : " + new String(parameterBytes));

        cipher.init(Cipher.DECRYPT_MODE, skspec, algorithmParms); //ToDO: Mit Alg Params geht es nicht

             byte[] decData = cipher.update(encryptedDataBytes);

        decRest = cipher.doFinal();

        byte[] allDecDataBytes = concatenate(decData, decRest);

        DataOutputStream outputStream = new DataOutputStream(new FileOutputStream(new File("decData.txt")));
        return allDecDataBytes;

    }

    public static PrivateKey getPrivateKey() {
        return privateRSAKey;
    }

    public static void setPrivateKey(PrivateKey privateKey) {
        RSF.privateRSAKey = privateKey;
    }

    public static PublicKey getPublicKey() {
        return publicRSAKey;
    }

    public static void setPublicKey(PublicKey publicKey) {
        RSF.publicRSAKey = publicKey;
    }

    public String getPrivateRSAFile() {
        return privateRSAFile;
    }

    public void setPrivateRSAFile(String privateRSAFile) {
        this.privateRSAFile = privateRSAFile;
    }

    public String getPublicRSAFile() {
        return publicRSAFile;
    }

    public void setPublicRSAFile(String publicRSAFile) {
        this.publicRSAFile = publicRSAFile;
    }

    private byte[] concatenate(byte[] ba1, byte[] ba2) {
        int len1 = ba1.length;
        int len2 = ba2.length;
        byte[] result = new byte[len1 + len2];

        // Fill with first array
        System.arraycopy(ba1, 0, result, 0, len1);
        // Fill with second array
        System.arraycopy(ba2, 0, result, len1, len2);

        return result;
    }
}
