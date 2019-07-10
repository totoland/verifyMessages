/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.toto.keytool;

import java.io.StringWriter;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author Thanapongn
 */
public class AppendXML {

    public static void main(String[] args) throws Exception {
        String xmlSignature = "<PARes id=\"po07133500\">"
                + "<version>1.0.2</version>"
                + "<Merchant>"
                + "<acqBIN>492100</acqBIN>"
                + "<merID>1234567890</merID>"
                + "</Merchant>"
                + "<Purchase>"
                + "<xid>MDAwMDAwMDAwMDAwNTA3NTU1MTA=</xid>"
                + "<date>20190307 13:34:56</date>"
                + "<purchAmount>000000000110</purchAmount>"
                + "<currency>764</currency>"
                + "<exponent>2</exponent>"
                + "</Purchase>"
                + "<pan>0000000000000100</pan>"
                + "<TX>"
                + "<time>20190307 13:35:10</time>"
                + "<status>Y</status>"
                + "<cavv>AAAAAAAAAAAAAAAARv/EzT51OhQ=</cavv>"
                + "<eci>05</eci>"
                + "<cavvAlgorithm>2</cavvAlgorithm>"
                + "</TX>"
                + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<SignedInfo>"
                + "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
                + "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                + "<Reference URI=\"\">"
                + "<Transforms>"
                + "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                + "</Transforms>"
                + "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                + "<DigestValue>ZYbPJvC5Hr0VPerXu+Gx3Ksl5TM=</DigestValue>"
                + "</Reference>"
                + "</SignedInfo>"
                + "<SignatureValue>X96qLS1hOpWvWA1JRDcEDTJ6P+fnUtdACaXZ5N2Y2vrJ83KiYX3XFsut3f/o10jHS8wJP6bX2cKXuQxWnjc8H+//1TD2ZKel99wzBC7c6pNElmu+MwUZWU4zL/yh7GjKivZuSU3mCWXK9H9IF0AIdkHQe326EI0zRCChsrOYaINB9touPnaYmZvMGx9HFNpfOAorkKPhJTTf7Ivn+2aDI/H88iEPapRJCWU15Qul4sG5MJncOkdikvF8syDPI5cIfmkBPN7uJsSf4rXDYH1prfD7jPId+WIvBHILIpOcm1sS4489tOW0n4TXHNLUHS+zup4j6Xwn7eltl0h15/3Iyg==</SignatureValue>"
                + "</Signature>"
                + "</PARes>";
        String appendKeyInfo = "<KeyInfo><X509Data><X509Certificate>MIIB6TCCAVKgAwIBAgIVAOUxGz0WuOsKMADx+1BGX2itczthMA0GCSqGSIb3DQEBBQUAMD4xCzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdDYXJhZGFzMQwwCgYDVQQLEwNQSVQxDzANBgNVBAMTBnBpdC1jYTAeFw0xMDA4MjYwNzUzMTBaFw0xMTA4MjYwNzUzMTBaMBExDzANBgNVBAMTBlZfU2lnbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzfBXBocH5pZc6kUMLnnCAx7QYkfYFq/n7+zRuZYSgdilEg1YQDKZsQlDkOhZIBbKDBZsfQbxTP4hIwjipWCZmuPiDTzkPGv8Mydk6A1cuZ2DRVTsjrwtjWMxN26ChNJyhxvqw8W1z8bTDnExraIwXsl2OwG4dNyreme/YK3hmBUCAwDUPaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQUFAAOBgQBUZ3kRVo+lP/x90pfAW5ecfYWBCv6ySFnm1563FYaiW8VNzVHXW7Nnt5Y1SvbwaMGjWQePUgJjhd2wTFxtPgG/Co/3emkjtAR7eiG4G8oZbN0NssdqB4xXxVv4wEfQTLRX8MwBv0oyJtJnUkjRhb7IoUV1vVkQ35GmeRb2StXvPw==</X509Certificate><X509Certificate>MIICHjCCAYegAwIBAgIVAPIEi+mOHBF9HNzSgQd4GHO8bJ95MA0GCSqGSIb3DQEBBQUAMEAxCzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdDYXJhZGFzMQwwCgYDVQQLEwNQSVQxETAPBgNVBAMTCHBpdC1yb290MB4XDTA0MDUwNzE2MjM1M1oXDTE0MDUwNTE2MjM1M1owPjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0NhcmFkYXMxDDAKBgNVBAsTA1BJVDEPMA0GA1UEAxMGcGl0LWNhMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfQlT5TzBwYVDeqgpueMOas6Rc3hbzz/1IPWbqy2yi8WCORXeQpLOHnBzz9JeefJgat2MzhEqC/yel8rsqIWFGBSP/4vShlIUgq+yIjlEA8XPvniPb6EFs2Vyhqrz5o90+8CSf+mmJU9QH/l0HPjas7JevM6M4tjsCD3q7gNbUSQIDAQABoxYwFDASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBBQUAA4GBAD/1xoc40RI+N4Ovm01NLDADyDC0YcaPGPbCx2OEUKO2yFUG5q+9LdZO2iQCGmx+tKfSIne4qniTKizeIZ6KRpoJCVbVEfwfIqTOjnwdtWLGCTJy5bv52zCKxDjpH6ybVD1P8G8QlWfIpAQyoIZbnttWEizhxuLNAbpM4bdfgS/b</X509Certificate><X509Certificate>MIICHzCCAYigAwIBAgIULLsSuNb5wJ0AJ3MkEqaVJe4ayrYwDQYJKoZIhvcNAQEFBQAwQDELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0NhcmFkYXMxDDAKBgNVBAsTA1BJVDERMA8GA1UEAxMIcGl0LXJvb3QwHhcNMDQwNTA3MTYyMzUwWhcNMTQwNTA1MTYyMzUwWjBAMQswCQYDVQQGEwJVUzEQMA4GA1UEChMHQ2FyYWRhczEMMAoGA1UECxMDUElUMREwDwYDVQQDEwhwaXQtcm9vdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAskqbW7oBwM1lCWNwC1obkgj4VV58G1AX7ERMWEIrQQlZ8uFdQ3FNkgMdtmx/XUjNF+zXTDmxe+K/lne+0KDwLWskqhS6gnkQmxZoR4FUovqRngoqU6bnnn0pM9gF/AI/vcdu7aowbF9S7TVlSw7IpxIQVjevEfohDpn/+oxljm0CAwEAAaMWMBQwEgYDVR0TAQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQUFAAOBgQBHTNIuf2yS8yDMreO3Ohr1qvTK/jBQkxZdfZbZiba7ItozfAu92tY35iblmElyMgduqmx1XSlbyfuQwXxR1a6Sb3pEN/fFUEyWXqmQuFXEe2KUu5J74tA8SX1fkcI0SNkxbQI4O3pBnmuyIrWAdIRzbM/4QV7yBxXh7g66koit9g==</X509Certificate></X509Data></KeyInfo>";
        String xml = addXMLKeyInfo(xmlSignature, appendKeyInfo);

        System.out.println(xml);

    }

    private static String addXMLKeyInfo(String xmlSignature, String appendKeyInfo) throws TransformerConfigurationException, TransformerException, Exception {
        Document docSignature = Signing.loadXMLFromString(xmlSignature);

        Document newXmlDocument = Signing.loadXMLFromString(appendKeyInfo);

        Node firstDocImportedNode = docSignature.importNode(newXmlDocument.getFirstChild(), true);
        docSignature.appendChild(firstDocImportedNode);

        StringWriter writer = new StringWriter();

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes"); // optional
        trans.setOutputProperty(OutputKeys.INDENT, "yes"); // optional
        trans.transform(new DOMSource(docSignature), new StreamResult(writer));

        return writer.toString();
    }

}
