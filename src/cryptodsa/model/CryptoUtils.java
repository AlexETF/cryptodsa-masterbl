/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptodsa.model;

import java.io.Console;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Stack;

/**
 *
 * @author ZM
 */
public class CryptoUtils {

    public static BigInteger CalculatePParameter(BigInteger q) {
        BigInteger p = q.add(BigInteger.ONE);
        for (BigInteger i = BigInteger.valueOf(1); i.intValue() > 0;) {
            p = q.multiply(i).add(BigInteger.ONE);
            if (p.isProbablePrime(100)) {
                return p;
            }
            i = i.add(BigInteger.ONE);
        }
        return p;
    }

    static BigInteger CalculateHParameter() {
        return new BigInteger("2");
    }

    static BigInteger CalculateGParameter(BigInteger q, BigInteger p) {
        return CalculateHParameter().modPow(p.subtract(BigInteger.ONE).divide(q), p);
    }

    static BigInteger GeneratePrivateKey(BigInteger q) {
        BigInteger privateKey = BigInteger.ONE;
        do {
            privateKey = new BigInteger(q.bitLength(), new Random(System.currentTimeMillis()));
        } while (privateKey.compareTo(q) >= 0);

        return privateKey;
    }

    static BigInteger GeneratePublicKey(BigInteger g, BigInteger privateKey, BigInteger p) {
        return g.modPow(privateKey, p);
    }

    static BigInteger CalculateHash(byte[] message) {
        //Calculate SHA-1 here 
        int sum = 0;
        for (int i = 0; i < message.length; i++) {
            sum += message[i];
        }
        return BigInteger.valueOf(((sum % 10) == 0) ? 2 : sum % 10);
    }

    static BigInteger CalculateKParameter(BigInteger q) {
        BigInteger value = new BigInteger(q.bitLength() - 2, new Random(System.currentTimeMillis()));
        return value;
    }

    static BigInteger CalculateRParameter(DSAKey privateKey, BigInteger k) {
        return privateKey.getG().modPow(k, privateKey.getP()).mod(privateKey.getQ());
    }

    static BigInteger CalculateIParameter(BigInteger q, BigInteger k) {
        return CalculateFactorization(q, k);
    }

    public static BigInteger CalculateFactorization(BigInteger q, BigInteger k) {

        BigInteger a = q;
        BigInteger b = k;
        Stack<Node> nodes = new Stack<Node>();
        while (a.remainder(b).compareTo(BigInteger.ZERO) != 0) {
            Node node = new Node();
            node.setValue(a);
            Element divisor = new Element();
            Element remainder = new Element();
            divisor.setValue(b);
            divisor.setMul(a.divide(b));
            remainder.setValue(a.remainder(b));
            remainder.setMul(BigInteger.ONE);
            a = b;
            b = remainder.getValue();
            node.setDivider(divisor);
            node.setRemainder(remainder);
            nodes.push(node);
        }
        Node root = invertNode(nodes.pop());
        root.setValue(BigInteger.ONE);
        while (nodes.size() > 0) {
            Node node = invertNode(nodes.pop());
            Element first = new Element();
            Element second = new Element();
            first.setValue(node.getDivider().getValue());
            first.setMul(root.getRemainder().getMul());
            second.setValue(node.getRemainder().getValue());
            second.setMul(root.getRemainder().getMul().multiply(node.getRemainder().getMul()).add(root.getDivider().getMul()));
            root.setDivider(first);
            root.setRemainder(second);
        }
        BigInteger result = root.getRemainder().getMul();
        if (result.compareTo(BigInteger.ZERO) < 0) {
            result = result.add(q);
        }

        return result;
    }

    private static Node invertNode(Node node) {
        node.getRemainder().setValue(node.getDivider().getValue());
        node.getRemainder().setMul(node.getDivider().getMul().negate());
        node.getDivider().setValue(node.getValue());
        node.getDivider().setMul(BigInteger.ONE);
        return node;
    }

    static BigInteger CalculateSParameter(BigInteger i, BigInteger h, BigInteger r, BigInteger key, BigInteger q) {
        return r.multiply(key).add(h).multiply(i).mod(q);
    }

}

class Node {

    private BigInteger value;
    private Element divider;
    private Element remainder;

    public BigInteger getValue() {
        return value;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }

    public Element getDivider() {
        return divider;
    }

    public void setDivider(Element divider) {
        this.divider = divider;
    }

    public Element getRemainder() {
        return remainder;
    }

    public void setRemainder(Element remainder) {
        this.remainder = remainder;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Value: " + value + System.lineSeparator());
        builder.append("Divider: " + divider + System.lineSeparator());
        builder.append("Remainder: " + remainder + System.lineSeparator());

        return builder.toString();
    }

}

class Element {

    private BigInteger value;
    private BigInteger mul;

    public Element() {
        this.value = BigInteger.ONE;
        this.mul = BigInteger.ONE;
    }

    public Element(BigInteger value) {
        this.value = value;
        this.mul = BigInteger.ONE;
    }

    public Element(BigInteger value, BigInteger mul) {
        this.value = value;
        this.mul = mul;
    }

    public BigInteger getValue() {
        return value;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }

    public BigInteger getMul() {
        return mul;
    }

    public void setMul(BigInteger mul) {
        this.mul = mul;
    }

    @Override
    public String toString() {
        return "Value: " + value + " Mul: " + mul;
    }
}
