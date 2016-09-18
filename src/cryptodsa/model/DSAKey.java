/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptodsa.model;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author ZM
 */
public class DSAKey {

    private BigInteger p;
    private BigInteger q;
    private BigInteger g;
    private BigInteger key;

    public DSAKey() {

    }

    public DSAKey(BigInteger key) {
        this.key = key;
    }

    public DSAKey(BigInteger q, BigInteger p, BigInteger g, BigInteger key) {
        this.q = q;
        this.p = p;
        this.g = g;
        this.key = key;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public BigInteger getKey() {
        return key;
    }

    public void setKey(BigInteger key) {
        this.key = key;
    }

    @Override
    public String toString() {
        StringBuilder key = new StringBuilder();

        key.append("Q:" + q.toString(16) + System.lineSeparator());
        key.append("P:" + p.toString(16) + System.lineSeparator());
        key.append("G:" + g.toString(16) + System.lineSeparator());
        key.append("Key:" + this.key.toString(16) + System.lineSeparator());

        return key.toString();
    }

    public static void writeKey(DSAKey key, String filePath) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        CryptoAES aes = new CryptoAES();
        File file = new File(filePath);
        if(!file.exists()){
            file.createNewFile();
        }
        System.out.println("File path: " + filePath);
        FileOutputStream writer = new FileOutputStream(filePath);
        writer.write(Base64.getEncoder().encode(aes.encrypt(key.toString().getBytes("utf-8"))));
        writer.flush();
        writer.close();
    }

    public static DSAKey loadKey(String filePath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        CryptoAES aes = new CryptoAES();
        byte[] bytes = aes.decrypt(Base64.getDecoder().decode(Files.readAllBytes(Paths.get(filePath))));
        String keyData = new String(bytes);

        DSAKey key = new DSAKey();
        String[] rows = keyData.split(System.lineSeparator());
        key.q = retrieveParameterFromDataString(rows[0]);
        key.p = retrieveParameterFromDataString(rows[1]);
        key.g = retrieveParameterFromDataString(rows[2]);
        key.key = retrieveParameterFromDataString(rows[3]);
        
        return key;
    }

    private static BigInteger retrieveParameterFromDataString(String data) {
        return new BigInteger(data.split(":")[1], 16);
    }

}
