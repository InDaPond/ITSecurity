package SSF;

import RSAKeyCreation.RSAKeyReader;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by Philipp Goemann on 07.06.2017.
 */
public class SSF {

    private String publicRSAFile;
    private String privateRSAFile;
    private PrivateKey prvRSAKey;
    private PublicKey pubRSAKey;
    private SecretKey secretAESKey;

    public SSF(String publicRSAFile, String privateRSAFile) {
        this.publicRSAFile = publicRSAFile;
        this.privateRSAFile = privateRSAFile;
    }

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        SSF ssf = new SSF("Philipp.pub", "Philipp.prv");
        RSAKeyReader keyReader = new RSAKeyReader();
        PrivateKey privateKey = keyReader.readPrivateKey(new File(ssf.getPrivateRSAFile()));
        ssf.setPrvRSAKey(privateKey);
        PublicKey publicKey = keyReader.readPublicKey(new File(ssf.getPublicRSAFile()));
        ssf.setPubRSAKey(publicKey);
        SecretKey secretKey = ssf.generateSecretKey();

        byte[] signature = ssf.createSignatureAndSign(secretKey);
        byte[] encryptedKeyRSA = ssf.encryptKeyWithRSA(secretKey);

        DataOutputStream outputStream = new DataOutputStream(new FileOutputStream(new File("Output.ssf")));


        outputStream.writeInt(encryptedKeyRSA.length);
        outputStream.write(encryptedKeyRSA);

        outputStream.writeInt(signature.length);
        outputStream.write(signature);

        String algorithm = secretKey.getAlgorithm();
        outputStream.write(algorithm.getBytes().length);
        outputStream.write(algorithm.getBytes());


        byte[] encryptedData = ssf.encryptData(new File("Input.txt"));


        outputStream.write(encryptedData);
        outputStream.flush();
        outputStream.close();
    }


    private byte[] encryptData(File file) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        DataInputStream inputStream = new DataInputStream(new FileInputStream(file));
        byte[] unencryptedDataBytes = new byte[(int) file.length()];
        inputStream.readFully(unencryptedDataBytes);


        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretAESKey);

        // nun werden die Daten verschluesselt
        // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
        byte[] encryptedData = cipher.update(unencryptedDataBytes);

        byte [] restData = cipher.doFinal();

        return concatenate(encryptedData, restData);
    }

    private SecretKey generateSecretKey() throws InvalidKeyException,
            NoSuchAlgorithmException {
        // AES-Schluessel generieren
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128); // Schluessellaenge als Parameter
        SecretKey skey = kg.generateKey();
        setSecretAESKey(skey);
        // Ergebnis
        return skey;
    }

    private byte[] createSignatureAndSign(Key key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        // die Nachricht als Byte-Array

        byte[] KeyBytes = key.getEncoded();
        Signature rsaSignature = null;
        byte[] signatureBytes = null;

        // als Erstes erzeugen wir das Signatur-Objekt
        rsaSignature = Signature.getInstance("SHA256withRSA");
        // zum Signieren benoetigen wir den privaten Schluessel (hier: RSA)
        rsaSignature.initSign(prvRSAKey);
        // Daten fuer die kryptographische Hashfunktion (hier: SHA-256)
        // liefern
        rsaSignature.update(KeyBytes);
        // Signaturbytes durch Verschluesselung des Hashwerts (mit privatem
        // RSA-Schluessel) erzeugen
        return rsaSignature.sign();

    }

    private byte[] encryptKeyWithRSA(Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Cipher-Objekt erzeugen und initialisieren mit AES-Algorithmus und
        // Parametern (z.B. IV-Erzeugung)
        // SUN-Default ist ECB-Modus (damit kein IV uebergeben werden muss)
        // und PKCS5Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Initialisierung zur Verschluesselung mit automatischer
        // Parametererzeugung
        cipher.init(Cipher.ENCRYPT_MODE, getPubRSAKey());

        // nun werden die Daten verschluesselt
        // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
        byte[] encData = cipher.update(key.getEncoded());

        // mit doFinal abschliessen (Rest inkl. Padding ..)
        byte[] encRest = cipher.doFinal();

        return concatenate(encData, encRest);
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

    private byte[] getAlgorithmParameter(SecretKey secretAESKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretAESKey);
        byte[] algorithmParameter = cipher.getParameters().getEncoded();
        return algorithmParameter;
    }

    public String getPublicRSAFile() {
        return publicRSAFile;
    }

    public String getPrivateRSAFile() {
        return privateRSAFile;
    }

    public PublicKey getPubRSAKey() {
        return pubRSAKey;
    }

    public void setPubRSAKey(PublicKey key) {
        this.pubRSAKey = key;
    }

    public void setPrvRSAKey(PrivateKey key) {
        this.prvRSAKey = key;
    }

    public void setSecretAESKey(SecretKey key) {
        this.secretAESKey = key;
    }


}