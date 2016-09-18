/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptodsa.model;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXBException;

/**
 *
 * @author ZM
 */
public class CryptoDSA {

    private DSAKey privateKey;
    private DSAKey publicKey;
    private String path;
    private byte[] arrayMessage;

    public CryptoDSA() {
        this.path = System.getProperty("user.dir");
    }

    public CryptoDSA(String path) {
        this.path = path;
    }

    public void generateDSAKeys(int keyLength) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {

        BigInteger q = new BigInteger(keyLength * 8, 100, new Random(System.currentTimeMillis()));
        BigInteger p = CryptoUtils.CalculatePParameter(q);
        BigInteger g = CryptoUtils.CalculateGParameter(q, p);

        privateKey = new DSAKey(q, p, g, CryptoUtils.GeneratePrivateKey(q));
        publicKey = new DSAKey(q, p, g, CryptoUtils.GeneratePublicKey(g, privateKey.getKey(), p));

        System.out.println("Private key: " + System.lineSeparator() + privateKey);
        System.out.println("Public key: " + System.lineSeparator() + publicKey);

        writeKeys(path);
    }

    public void signFile(String filePath, String keyPath) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("File does not exist");
        }
        privateKey = DSAKey.loadKey(keyPath);
        System.out.println(privateKey);

        StringBuilder builder = new StringBuilder();
        BufferedReader reader = new BufferedReader(new FileReader(new File(filePath)));
        String line = "";
        while ((line = reader.readLine()) != null) {
            builder.append(line + "\n");
        }
        reader.close();

        BigInteger h = CryptoUtils.CalculateHash(builder.toString().getBytes("UTF-8"));
        BigInteger k = CryptoUtils.CalculateKParameter(privateKey.getQ());
        BigInteger r = CryptoUtils.CalculateRParameter(privateKey, k);

        BigInteger i = CryptoUtils.CalculateIParameter(privateKey.getQ(), k);
        BigInteger s = CryptoUtils.CalculateSParameter(i, h, r, privateKey.getKey(), privateKey.getQ());

        SignedMessage signed = new SignedMessage(builder.toString(), r.toString(16), s.toString(16));
        SignedMessage.serializeToXml(signed, path + File.separatorChar + "message.xml");
        
        System.out.println("File path: " + path + File.separatorChar + "message.xml");
    }

    public boolean verifySignature(String filePath, String keyPath) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("File does not exist");
        }
        publicKey = DSAKey.loadKey(keyPath);
        System.out.println(publicKey);

        SignedMessage signed = SignedMessage.deserializeFromXml(filePath);

        BigInteger h = CryptoUtils.CalculateHash(signed.getOriginalMessage().getBytes("UTF-8"));
        BigInteger s = new BigInteger(signed.getS(), 16);
        BigInteger r = new BigInteger(signed.getR(), 16);
        BigInteger w = CryptoUtils.CalculateFactorization(publicKey.getQ(), s);
        BigInteger u1 = h.multiply(w).mod(publicKey.getQ());
        BigInteger u2 = r.multiply(w).mod(publicKey.getQ());

        BigInteger g_exp_u1 = publicKey.getG().modPow(u1, publicKey.getP());
        BigInteger key_exp_u2 = publicKey.getKey().modPow(u2, publicKey.getP());
        BigInteger v = g_exp_u1.multiply(key_exp_u2).mod(publicKey.getP()).mod(publicKey.getQ());

        return (v.compareTo(r) == 0);
    }

    private void writeKeys(String path) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JAXBException {
        DSAKey.writeKey(privateKey, path + File.separatorChar + "private.dsa");
        DSAKey.writeKey(publicKey, path + File.separatorChar + "public.dsa");
    }

}
