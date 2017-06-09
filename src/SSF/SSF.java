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

    /**
    * java SSF KMueller.prv FMeier.pub Brief.pdf Brief.ssf
    */
    //D:\Uni\Semester5\ITS\Praktikum3\ITSecurity\Test.prv D:\Uni\Semester5\ITS\Praktikum3\ITSecurity\Test.pub D:\Uni\Semester5\ITS\Praktikum3\ITSecurity\ITSAufgabe3.pdf D:\Uni\Semester5\ITS\Praktikum3\ITSecurity\OutputFile.ssf
    public static void main(String[] args) throws Exception {
        String privateKeyFile = args[0];
        String publicKeyFile = args[1];
        String inputFile = args[2];
        String outputFile = args[3];

        new SSF(privateKeyFile,publicKeyFile,inputFile,outputFile);
    }

    public SSF(String privateKeyFile, String publicKeyFile, String input, String output) throws Exception {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        SecretKey secretAESKey;
        Signature signature;
        Cipher cipher;
        File file;
            RSAKeyReader keyReader = new RSAKeyReader();
            /**
            //a) Einlesen eines privaten RSA‐Schlüssels (.prv) aus einer Datei gemäß Aufgabenteil 1. 
            //b) Einlesen eines öffentlichen RSA‐Schlüssels (.pub) aus einer Datei gemäß Aufgabenteil 1. 
             */
            privateKey = keyReader.loadPrivKey(privateKeyFile);
            publicKey = keyReader.loadPubKey(publicKeyFile);

            /**
              c) Erzeugen eines geheimen Schlüssels für den AES‐Algorithmus mit der Schlüssellänge 128 Bit 
            */
            secretAESKey = generateAESKey();

            /**
             * d) Erzeugung einer Signatur für den geheimen Schlüssel aus c) mit dem privaten RSA‐Schlüssel 
               (Algorithmus: „SHA256withRSA“) 
             */
            signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(secretAESKey.getEncoded());
            byte[] signatureBytes = signature.sign();

            /**
            e) Verschlüsselung des geheimen Schlüssels aus c) mit dem öffentlichen RSA‐Schlüssel (Algorithmus: „RSA“) 
            */
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherData = cipher.update(secretAESKey.getEncoded());
            byte[] cipherRest = cipher.doFinal();
            byte[] cipherText = concatenate(cipherData,cipherRest);

            /**
            f) Einlesen einer Dokumentendatei, Verschlüsseln der Dateidaten mit dem symmetrischen AES‐
            Algorithmus (geheimer Schlüssel aus c) im Counter‐Mode („CTR“)
            */
            File inputFile = new File(input);
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            Cipher inputCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            inputCipher.init(Cipher.ENCRYPT_MODE, secretAESKey);
            byte[] readInput = new byte[8];
            int len;
            byte[] inputCipherFile = new byte[0];
            while ((len = fileInputStream.read(readInput)) > 0) {
                inputCipherFile = concatenate(inputCipherFile,inputCipher.update(readInput.clone()));
            }
            byte[] inputCipherFinal = inputCipher.doFinal();
            byte[] inputCipherText = concatenate(inputCipherFile,inputCipherFinal);

            /**
            Erzeugen einer Ausgabedatei
            */
            File outputFile = new File(output);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);

            /**
            1. Länge des verschlüsselten geheimen Schlüssels (integer) 
            2. Verschlüsselter geheimer Schlüssel (Bytefolge) 
            3. Länge der Signatur des geheimen Schlüssels (integer) 
            4. Signatur des geheimen Schlüssels (Bytefolge) 
            5. Länge der algorithmischen Parameter des geheimen Schlüssels 
            6. Algorithmische Parameter des geheimen Schlüssels (Bytefolge) 
            7. Verschlüsselte Dateidaten (Ergebnis von f) (Bytefolge) 
            */
            dataOutputStream.writeInt(cipherText.length);
            dataOutputStream.write(cipherText,0,cipherText.length);
            dataOutputStream.writeInt(signatureBytes.length);
            dataOutputStream.write(signatureBytes,0,signatureBytes.length);
            dataOutputStream.writeInt(inputCipher.getParameters().getEncoded().length);
            dataOutputStream.write(inputCipher.getParameters().getEncoded());
            dataOutputStream.write(inputCipherText,0,inputCipherText.length);
            dataOutputStream.close();
    }

    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        return kgen.generateKey();
    }

    public static byte[] concatenate(byte[] ba1, byte[] ba2) {
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