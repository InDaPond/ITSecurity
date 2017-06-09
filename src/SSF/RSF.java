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
    /**
    java RSF FMeier.prv KMueller.pub Brief.ssf Brief.pdf
    */
    public static void main(String[] args) throws Exception {
        String privateKeyFile = args[0];
        String publicKeyFile = args[1];
        String inputFile = args[2];
        String outputFile = args[3];

        new RSF(privateKeyFile,publicKeyFile,inputFile,outputFile);
    }

    public RSF(String privKeyFile, String pubKeyFile, String input, String output) throws Exception {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
            RSAKeyReader keyReader = new RSAKeyReader();

            /**
            a) Einlesen eines öffentlichen RSA‐Schlüssels aus einer Datei gemäß Aufgabenteil 1. 
            */
            privateKey = keyReader.loadPrivKey(privKeyFile);

            /**
            b) Einlesen eines privaten RSA‐Schlüssels aus einer Datei gemäß Aufgabenteil 1. 
            */
            publicKey = keyReader.loadPubKey(pubKeyFile);

            /**
            c) Einlesen einer .ssf‐Datei gemäß Aufgabenteil 2, Entschlüsselung des geheimen Schlüssels mit 
            dem privaten RSA‐Schlüssel
            */
            File inputFile = new File(input);
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            DataInputStream dataInputStream = new DataInputStream((fileInputStream));

            /**
            Schlüssel auslesen
            */
            int keyLength = dataInputStream.readInt();
            byte[] aesKey = new byte[keyLength];
            dataInputStream.read(aesKey);

            /**
             Signatur auslesen
            */
            int signatureLength =  dataInputStream.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dataInputStream.read(signatureBytes);

            /**
             Algorithmus Parameter auslesen
            */
            int rsaParamsLength = dataInputStream.readInt();
            byte[] rsaParams = new byte[rsaParamsLength];
            dataInputStream.read(rsaParams);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] decryptedAesKey = cipher.doFinal(aesKey);

            /**
            Entschlüsselung der Dateidaten mit dem geheimen Schlüssel (AES im Counter‐Mode) – mit Anwendung der übermittelten algorithmischen Parameter – sowie 
            Erzeugung einer Klartext‐Ausgabedatei.*/
            SecretKeySpec skspec = new SecretKeySpec(decryptedAesKey, "AES");

            /**
              mit Anwendung der übermittelten algorithmischen Parameter
            */
            AlgorithmParameters algorithmParms = AlgorithmParameters
                    .getInstance("AES");
            algorithmParms.init(rsaParams);

            Cipher inputCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            inputCipher.init(Cipher.DECRYPT_MODE,skspec,algorithmParms);

            byte[] readInput = new byte[8];
            int len;
            byte[] inputCipherFile = new byte[0];
            while ((len = fileInputStream.read(readInput)) > 0) {
                inputCipherFile = concatenate(inputCipherFile,inputCipher.update(readInput.clone()));
            }
            byte[] inputCipherFinal = inputCipher.doFinal();

            /**
             Erzeugung einer Klartext‐Ausgabedatei. 
            */
            File outputFile = new File(output);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);
            dataOutputStream.write(inputCipherFile);

            dataInputStream.close();
            dataOutputStream.close();

            /**
            d) Überprüfung der Signatur für den geheimen Schlüssel aus c) mit dem öffentlichen RSA‐Schlüssel 
            (Algorithmus: „SHA256withRSA“) 
            */
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            /**
            // Echter AES Key, der auch verschlüsselt wurde
            */
            signature.update(decryptedAesKey);
            if(signature.verify(signatureBytes)){
                System.out.println("Signature Verified");
            } else {
                System.out.println("Signature could not be verified");
            }
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
