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

    private String rsapubFile;
    private String rsaprvFile;
    private PrivateKey prvRSAKey;
    private PublicKey pubRSAKey;
    private SecretKey sKey;

    public SSF(String rsapubFile, String rsaprvFile) {
        this.rsapubFile = rsapubFile;
        this.rsaprvFile = rsaprvFile;
    }

    public String getRsapubFile() {
        return rsapubFile;
    }

    public String getRsaprvFile() {
        return rsaprvFile;
    }

    public  PublicKey getPubRSAKey(){
        return pubRSAKey;
    }

    public void setPrvRSAKey(PrivateKey key) {
        this.prvRSAKey = key;
    }

    public void setPubRSAKey(PublicKey key) {
        this.pubRSAKey = key;
    }

    public void setsKey(SecretKey key) {
        this.sKey = key;
    }


    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        SSF ssf = new SSF("Philipp.pub", "Philipp.prv");
        RSAKeyReader keyReader = new RSAKeyReader();
        PrivateKey prvKey = keyReader.readPrivateKey(new File(ssf.getRsaprvFile()));
        ssf.setPrvRSAKey(prvKey);
        PublicKey pubKey = keyReader.readPublicKey(new File(ssf.getRsapubFile()));
        ssf.setPubRSAKey(pubKey);
        DataOutputStream os = new DataOutputStream(new FileOutputStream(new File("Output.ssf")));
        SecretKey skey = ssf.generateSecretKey();
        byte[] signature = ssf.createSignatureAndSign(skey);
        byte[] encryptedWithRSA = ssf.encryptKeyWithRSA(skey);
        os.writeInt(encryptedWithRSA.length);
        os.write(encryptedWithRSA);
        os.writeInt(signature.length);
        os.write(signature);
        String algorithm = skey.getAlgorithm();
        os.write(algorithm.getBytes().length);
        os.write(algorithm.getBytes());




    }


    public SecretKey generateSecretKey() throws InvalidKeyException,
            NoSuchAlgorithmException {
        // AES-Schluessel generieren
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128); // Schluessellaenge als Parameter
        SecretKey skey = kg.generateKey();
        setsKey(skey);
        // Ergebnis
        return skey;
    }

    public byte[] createSignatureAndSign(Key key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

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

    public byte[] encryptKeyWithRSA(Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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


}