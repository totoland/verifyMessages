/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.toto.keytool;

import com.sun.org.apache.xerces.internal.dom.DocumentImpl;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import static java.util.Collections.singletonList;
import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import static javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;

/**
 *
 * @author Thanapongn
 */
public class VerifyRSAsha256 {

    /*
        Compile:
        clear && javac verifyRSAsha256.java && java verifyRSAsha256

        Create private key:
        openssl genrsa -des3 -out encrypted.pem 2048 && openssl rsa -in encrypted.pem -out private.pem -outform PEM && openssl rsa -in private.pem -pubout > public.pem

        Create signature:
        /bin/echo -n "some text that you want to be trusted" > data.txt
        openssl dgst -sha256 -sign private.pem data.txt > signature.tmp
        base64 signature.tmp

        Verify signature:
        openssl dgst -sha256 -verify public.pem -signature signature.tmp data.txt
     */
    public static void main(String args[]) {
        String publicKey
                = //  "-----BEGIN PUBLIC KEY-----"+
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt44wPxaFIE1eI5ROLqIP"
                + "PvI4x0g02KViWJJQK+dyDU3EAPr6r1XDQoYC+pbgxqw9YBSGn4PKwpgqJhVtR3Ka"
                + "WeXTv/Lxy2qU0b8m/oOBIoxEMlbHB0gtBLYo72DxLbPyJXs0BHgKNK1LUZ2XCe3Z"
                + "SpNFmgVD2M1319PiMqIZdjiKMCPpPFRDeKGBsVFg25fF0VbC1gRwM4jvNbvoFFys"
                + "BBfe9YuJe7vj7FaIHfrSvyI80sE0oQkRju9MGMiY4KbJ39XnvlcYZeuZ51kIrxWi"
                + "v5r6Q9nYHtqI1RIrgnkG3xZr9VMOFeSsTzr/xaund5H1tquPYMimyCAH+DdSXlZ+"
                + "OwIDAQAB";
        //  "-----END PUBLIC KEY-----";

        byte[] signature, data;

        // the signature is a binary data and I encoded it with base64, so the signature must be decoded from base64 to binary again
        signature = DatatypeConverter.parseBase64Binary("ea9KSw1VihVvUaACrnZvCC1gloneDO/Hgfi8JfdKEOTHzXh+tat0CYCgyf/rduZq+OfWxW8ImpaIHeYY7K6if/tu20oTMWxOFKKNMgPVPcr2GtkRWCbJwCUdjsBmMBEPsRlciViElaqB7IZE8NZLjGdTXUdS+jItcWmmC5o/dIVebGuptTGg1Q7dLqrvpTf2n2O9uhngdXRbIb3J66PkUZRLGG7LL81j4b/BU6cJmzlUmvC82vdjt3QHV/+EemQIPsWmJAWKkgRNFAPH4VgnUliMNgTZe5eld22kK+jg4hXcobsNLkqRtgMYXbmpINiXQPbRlMuI4WFoJ4fGk8o8Cw==");

        // the signature length have to be 256 bytes
        System.out.print("Signature length 256 = ");
        System.out.println(signature.length);

        // the data used the generate the signature
        data = "some text that you want to be trusted".getBytes();

        // verify if signature is ok
        try {
            System.out.println(verify(data, signature, publicKey));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        // if any byte of data changes (ex: change last byte from d to D)
        data = "some text that you want to be trusteD".getBytes();

        // the signature doesn't math and method verify will fail
        try {
            System.out.println(verify(data, signature, publicKey));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        
        try {
            sign();
        } catch (Exception ex) {
            ex.printStackTrace();
        } 

    }

    private static boolean verify(byte[] data, byte[] signature, String publicKey) throws GeneralSecurityException {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(DatatypeConverter.parseBase64Binary(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private static Document sign() throws InstantiationException, IllegalAccessException, ClassNotFoundException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, MarshalException, XMLSignatureException,
            FileNotFoundException, TransformerException, javax.xml.crypto.MarshalException {

        Document doc = new DocumentImpl();
        
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

        DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);
        Transform transform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Reference reference = fac.newReference("", digestMethod, singletonList(transform), null, null);
        SignatureMethod signatureMethod = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null);

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, singletonList(reference));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();

        // output the resulting document
        OutputStream os;

        os = new FileOutputStream("D:/xmlOut.xml");

        trans.transform(new DOMSource(doc), new StreamResult(os));
        return doc;

    }
}
