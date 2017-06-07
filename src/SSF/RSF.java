package SSF;

import RSAKeyCreation.RSAKeyReader;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
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

    public static void main(String args[]) throws InvalidKeySpecException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        RSF rsf = new RSF("Philipp.pub", "Philipp.prv");
        RSAKeyReader keyReader = new RSAKeyReader();
        PrivateKey privateKey = keyReader.readPrivateKey(new File(rsf.getPrivateRSAFile()));
        rsf.setPrivateKey(privateKey);
        PublicKey publicKey = keyReader.readPublicKey(new File(rsf.getPublicRSAFile()));
        rsf.setPublicKey(publicKey);

        rsf.readAndVerifySecureFile(new File("Output.ssf"));
    }

    private String readAndVerifySecureFile(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        byte[] encryptedSecretKey = null;
        byte[] signatureBytes = null;
        byte[] pubKeyBytes = null;
        byte[] parameterBytes = null;
        byte[] encryptedData = null;

        // die Datei wird geoeffnet und die Daten gelesen
        DataInputStream inputStream = new DataInputStream(new FileInputStream(file));


        // die Laenge der Nachricht
        int secretKeyLength = inputStream.readInt();
        encryptedSecretKey = new byte[secretKeyLength];
        // die Nachricht
        inputStream.read(encryptedSecretKey);


        // die Laenge der Signatur
        int signatureLength = inputStream.readInt();
        signatureBytes = new byte[signatureLength];
        // die Signatur
        inputStream.read(signatureBytes);


        // die Laenge des oeffentlichen Schluessels
        int parameterLength = inputStream.readInt();
        parameterBytes = new byte[parameterLength];
        // der oeffentliche Schluessel
        inputStream.read(parameterBytes);

        inputStream.read(encryptedData);

        // Datei schliessen
        inputStream.close();

        SecretKey aesSecretKey = decryptSecretKey(encryptedSecretKey, privateRSAKey);




        // aus dem Byte-Array koennen wir eine X.509-Schluesselspezifikation
        // erzeugen
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);

        // nun wird aus der Spezifikation wieder abgeschlossener public key
        // erzeugt
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFac.generatePublic(x509KeySpec);

        // Nun wird die Signatur ueberprueft
        // als Erstes erzeugen wir das Signatur-Objekt
        Signature rsaSig = Signature.getInstance("SHA256withRSA");
        // zum Verifizieren benoetigen wir den oeffentlichen Schluessel
        rsaSig.initVerify(pubKey);
        // Daten fuer die kryptographische Hashfunktion (hier: SHA-256)
        // liefern
        rsaSig.update(encryptedData);

        // Signatur verifizieren:
        // 1. Verschluesselung der Signatur (mit oeffentlichem
        // RSA-Schluessel)
        // 2. Pr�fung: Ergebnis aus 1. == kryptogr. Hashwert der messageBytes?
        boolean ok = rsaSig.verify(signatureBytes);
        if (ok)
            System.out.println("Signatur erfolgreich verifiziert!");
        else
            System.out.println("Signatur konnte nicht verifiziert werden!");


        // als Ergebnis liefern wir die urpspruengliche Nachricht
        return new String(encryptedData);


    }

    public SecretKey decryptSecretKey(byte[] encryptedKey, PrivateKey privateKey) {
        //TODO
        return null;
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
}
