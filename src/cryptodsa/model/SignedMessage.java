/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptodsa.model;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author ZM
 */
@XmlRootElement(name = "digital_signature")
@XmlAccessorType(XmlAccessType.NONE)
public class SignedMessage {

    @XmlElement(name = "original")
    private String originalMessage;

    @XmlElement(name = "R")
    private String R;

    @XmlElement(name = "S")
    private String S;

    public SignedMessage() {

    }

    public SignedMessage(String originalMessage, String R, String S) {
        this.originalMessage = originalMessage;
        this.R = R;
        this.S = S;
    }

    public String getOriginalMessage() {
        return originalMessage;
    }

    public void setOriginalMessage(String originalMessage) {
        this.originalMessage = originalMessage;
    }

    public String getR() {
        return R;
    }

    public void setR(String R) {
        this.R = R;
    }

    public String getS() {
        return S;
    }

    public void setS(String S) {
        this.S = S;
    }

    public static void serializeToXml(SignedMessage message, String path) throws JAXBException, IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(new File(path)));
        JAXBContext context = JAXBContext.newInstance(SignedMessage.class);
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        m.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
        m.marshal(message, writer);
        writer.close();
    }
    
    public static SignedMessage deserializeFromXml(String path) throws JAXBException, IOException {
        BufferedReader reader = new BufferedReader(new FileReader(new File(path)));
        JAXBContext context = JAXBContext.newInstance(SignedMessage.class);
        Unmarshaller m = context.createUnmarshaller();
        SignedMessage message = (SignedMessage)m.unmarshal(reader);
        reader.close();
        return message;
    }

}
