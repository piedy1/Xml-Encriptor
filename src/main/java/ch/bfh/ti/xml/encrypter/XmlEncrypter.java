/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package ch.bfh.ti.xml.encrypter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.w3c.dom.Document;

/**
 *
 * @author Yandy
 */
public class XmlEncrypter {
    
    static {
    org.apache.xml.security.Init.init();
    }
    
    public static void main(String[] args) throws Exception{
        
        // Instantiate the document to be encrypted.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream("src/main/java/ch/bfh/ti/xml/input/animal.xml"));
        
        // Load the KeyStore and get the signing key and certificate.
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream("src/main/java/ch/bfh/ti/xml/util/KeyStore.jce"), "changeit".toCharArray());
        KeyStore.PrivateKeyEntry keyEntry
                = (KeyStore.PrivateKeyEntry) ks.getEntry("bob", new KeyStore.PasswordProtection("changeit".toCharArray()));
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        
        //Get the public key to encrypt the symmetric key
        PublicKey publicKey = cert.getPublicKey();
        
        //The symmectric key to encrypt and decrypt the data
        String jceAlgorithmName = "AES";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(128);
        Key symmetrickey = keyGenerator.generateKey();
        
        // <code>XMLCipher</code> encrypts and decrypts the contents of
        // <code>Document</code>s, <code>Element</code>s and <code>Element</code>
        // contents
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);

        
        // Initializes this cipher with a key.
        // The cipher is initialized for one of the 
        // following four operations: encryption, decryption, key wrapping or key unwrapping, depending on the value of opmode. 
        // For WRAP and ENCRYPT modes, this also initialises the internal EncryptedKey or EncryptedData 
        // (with a CipherValue) structure that will be used during the ensuing operations. 
        // This can be obtained (in order to modify KeyInfo elements etc. prior to finalising the encryption) by calling
        // XMLCipher.getEncryptedData or XMLCipher.getEncryptedKey
        keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
        
        // Encrypts a key to an EncryptedKey structure
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, symmetrickey);

        //Algorithm for the EncryptionMethod of the EncryptedData
        // To encrypt the data
      

        XMLCipher xmlCipher
                = XMLCipher.getInstance(XMLCipher.AES_128);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetrickey);
        
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        org.apache.xml.security.keys.KeyInfo keyInfo = new org.apache.xml.security.keys.KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        /*
         * doFinal -
         * "true" below indicates that we want to encrypt element's content
         * and not the element itself. Also, the doFinal method would
         * modify the document by replacing the EncrypteData element
         * for the data to be encrypted.
         */
        xmlCipher.doFinal(doc, doc.getDocumentElement());       
        
         outputDocToFile(doc, "src/main/java/ch/bfh/ti/xml/output/encriptedAnimal.xml");
    }  
    
    private static void outputDocToFile(Document doc, String fileName) throws Exception {
        File encryptionFile = new File(fileName);
        FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(f);
        transformer.transform(source, result);

        f.close();
        System.out.println(
                "Wrote document containing encrypted data to " + encryptionFile.toURI().toURL().toString()
        );
    }
}
