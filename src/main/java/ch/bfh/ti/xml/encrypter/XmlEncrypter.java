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
import javax.crypto.KeyGenerator;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
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
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream("src/main/resources/ch/bfh/ti/xml/input/animal.xml"));
        
       
        // Create a keystore with type JCEKS
        KeyStore ks = KeyStore.getInstance("JCEKS");
        
        // Load the keystore 
        ks.load(new FileInputStream("src/main/resources/ch/bfh/ti/xml/util/KeyStore.jce"), "changeit".toCharArray());
        
        // get the signing key
        KeyStore.PrivateKeyEntry keyEntry
                = (KeyStore.PrivateKeyEntry) ks.getEntry("alice", new KeyStore.PasswordProtection("changeit".toCharArray()));
        
        // get the certificate, which is the container of the public key
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        
        //Get the public key to encrypt the symmetric key
        PublicKey publicKey = cert.getPublicKey();
        
        //The symmectric key to encrypt and decrypt the data
        String jceAlgorithmName = "AES";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(128);
        Key symmetrickey = keyGenerator.generateKey();
        
        // Alternative generate a symmetric key with Triple DES
        // Key symmetricKey = KeyGenerator.getInstance("DESede").generateKey();
        
        // <code>XMLCipher</code> encrypts and decrypts the contents of
        // <code>Document</code>s, <code>Element</code>s and <code>Element</code> contents
        // Create a cipher based in an RSA algorithm.
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
        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        /*
         * doFinal -
         * "true" below indicates that we want to encrypt element's content
         * and not the element itself. Also, the doFinal method would
         * modify the document by replacing the EncrypteData element
         * for the data to be encrypted.
         */
        xmlCipher.doFinal(doc, doc.getDocumentElement(), true);       
        
         outputDocToFile(doc, "src/main/resources/ch/bfh/ti/xml/output/encriptedAnimal.xml");
    }  
    
    private static void outputDocToFile(Document doc, String fileName) throws Exception {
        File encryptionFile = new File(fileName);
        FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
//        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(f);
        transformer.transform(source, result);

        f.close();
        System.out.println(
                "Wrote document containing encrypted data to " + encryptionFile.toURI().toURL().toString()
        );
    }
}
