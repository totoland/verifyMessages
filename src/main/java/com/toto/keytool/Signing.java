package com.toto.keytool;


import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class Signing {
	
        /***
         * 
         * @param xmlString PaResp
         * @param withKeyInfo
         * @return XML String Signature
         * @throws NoSuchAlgorithmException
         * @throws InvalidAlgorithmParameterException
         * @throws Exception 
         */
        public String getXmlSigning(String xmlString,boolean withKeyInfo) throws NoSuchAlgorithmException, 
                InvalidAlgorithmParameterException, Exception {
            
            // Create a DOM XMLSignatureFactory that will be used to generate the
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                    null, null);

            // Create the SignedInfo
            SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                    (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(XMLSecurityConstants.NS_XMLDSIG_RSASHA1, null),
                    Collections.singletonList(ref));

            // RSA KeyPair
            KeyPair kp = SecureMessage.getKeyPairFromKeyStore();

            // Create a KeyValue containing the RSA PublicKey that was generated
            KeyInfoFactory kif = fac.getKeyInfoFactory();
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) SecureMessage.getCertificate();
            List x509Content = new ArrayList();
            x509Content.add(cert.getSubjectX500Principal().getName());
            x509Content.add(cert);
            X509Data xd = kif.newX509Data(x509Content);

            // Instantiate the document to be signed
            Document doc = loadXMLFromString(xmlString);

            // Create a DOMSignContext and specify the DSA PrivateKey and
            // location of the resulting XMLSignature's parent element
            DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

            // Create the XMLSignature (but don't sign it yet)
            // Create a KeyInfo and add the KeyValue to it
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
            XMLSignature signature = withKeyInfo?fac.newXMLSignature(si, ki):
                    fac.newXMLSignature(si, null);

            // Marshal, generate (and sign) the enveloped signature
            signature.sign(dsc);

            // output the resulting document
            StringWriter writer = new StringWriter();

            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(writer));

            return writer.toString();
        }
        
        public static Document loadXMLFromString(String xml) throws Exception{
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(xml));
            return builder.parse(is);
        }
}
