package SSF;

import RSAKeyCreation.RSAKeyReader;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
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

    public static void main(String args[]) throws InvalidKeySpecException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        RSF rsf = new RSF("Philipp.pub", "Philipp.prv");
        RSAKeyReader keyReader = new RSAKeyReader();
        PrivateKey privateKey = keyReader.readPrivateKey(new File(rsf.getPrivateRSAFile()));
        rsf.setPrivateKey(privateKey);
        PublicKey publicKey = keyReader.readPublicKey(new File(rsf.getPublicRSAFile()));
        rsf.setPublicKey(publicKey);

        rsf.readAndVerifySecureFile(new File("Output.ssf"));
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

    private String readAndVerifySecureFile(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
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


        encryptedData = new byte[(int) file.length()];
        inputStream.read(encryptedData);

        // Datei schliessen
        inputStream.close();

        SecretKey aesSecretKey = decryptSecretKey(encryptedSecretKey, privateRSAKey);

        byte[] aesSecretKeyBytes = aesSecretKey.getEncoded();

        byte[] decryptedData = decryptData(encryptedData, aesSecretKeyBytes, parameterBytes);

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

//    public SecretKey decryptSecretKey(byte[] encryptedKey, PrivateKey privateKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
//        // Cipher-Objekt erzeugen und initialisieren mit AES-Algorithmus und
//        // Parametern (z.B. IV-Erzeugung)
//        // SUN-Default ist ECB-Modus (damit kein IV uebergeben werden muss)
//        // und PKCS5Padding
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//
//        // Initialisierung zur Verschluesselung mit automatischer
//        // Parametererzeugung
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//
//        //Todo stimmt das so?s
//        byte[] decSkeyByte = cipher.doFinal(encryptedKey);
//        SecretKey decSkey = new SecretKeySpec(decSkeyByte, "AES");
//        System.out.println(decSkey);
//        return decSkey;
//    }

    public SecretKey decryptSecretKey(byte[] encryptedKey, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher;
        byte[] decryptedData = null;
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedData = cipher.doFinal(encryptedKey);
        SecretKey decSkey = new SecretKeySpec(decryptedData, "AES");
        return decSkey;
    }


    public byte[] decryptData(byte[] cipherBytes, byte[] secretKeyBytes, byte[] parameterBytes) throws NoSuchAlgorithmException,
            IOException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        // Datenbytes entschluesseln

        // Zuerst muss aus der Bytefolge eine neue AES-Schluesselspezifikation
        // erzeugt werden (transparenter Schluessel)
        SecretKeySpec skspec = new SecretKeySpec(secretKeyBytes, "AES");

        // Algorithmische Parameter aus Parameterbytes ermitteln (z.B. IV)
        AlgorithmParameters algorithmParms = AlgorithmParameters
                .getInstance("AES");

        algorithmParms.init(parameterBytes);

        // Cipher-Objekt zur Entschluesselung erzeugen
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // mit diesem Schluessel wird nun die AES-Chiffre im DECRYPT MODE
        // initialisiert (inkl. AlgorithmParameters fuer den IV)
        cipher.init(Cipher.DECRYPT_MODE, skspec, algorithmParms);

        // und die Daten entschluesselt
        byte[] decData = cipher.update(cipherBytes);

        // mit doFinal abschliessen (Rest inkl. Padding ..)
        byte[] decRest = cipher.doFinal();

        byte[] allDecDataBytes = concatenate(decData, decRest);

        // Rueckgabe: die entschluesselten Klartextbytes
        return allDecDataBytes;
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

    public static PrivateKey getPrivateRSAKey() {
        return privateRSAKey;
    }

    public static PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }
}
