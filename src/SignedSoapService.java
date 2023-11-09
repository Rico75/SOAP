import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.Endpoint;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

@WebService
public class SignedSoapService {
    private static final String KEYSTORE_PATH = "path/to/your/keystore.jks";
    private static final String KEYSTORE_PASSWORD = "yourkeystorepassword";
    private static final String ALIAS = "youralias";
    private static final KeyStore keystore;
    private static final PrivateKey privateKey;
    private static final X509Certificate cert;
    private static final SOAPMessage soapMessage;
//    private static final XMLSignatureFactory factory;
    private static final KeyInfoFactory kif;

    static {
        try {
            // Load keystore
            keystore = KeyStore.getInstance("JKS");
            keystore.load(SignedSoapService.class.getClassLoader().getResourceAsStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            // Get private key and certificate from keystore
            privateKey = (PrivateKey) keystore.getKey(ALIAS, KEYSTORE_PASSWORD.toCharArray());
            cert = (X509Certificate) keystore.getCertificate(ALIAS);
            // Get the SOAP message
            // Assuming you have a SOAPMessage object named 'soapMessage'
            MessageFactory mf = MessageFactory.newInstance();
            soapMessage = mf.createMessage();
            // Create a DOMSignContext and specify the private key and location of the resulting XMLSignature's parent element
            DOMSignContext dsc = new DOMSignContext(privateKey, soapMessage.getSOAPPart().getEnvelope());
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            Reference ref = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
            // Create a KeyInfo and add the X509Data content
            kif = factory.getKeyInfoFactory();
            X509Data xd = kif.newX509Data(Collections.singletonList(cert.getSubjectX500Principal().getName()));
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
            SignedInfo si = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                            (C14NMethodParameterSpec) null), factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                    Collections.singletonList(ref));
            // Create the XMLSignature (but don't sign it yet)
            XMLSignature signature = factory.newXMLSignature(si, ki);
            // Marshal, generate, and sign the enveloped signature
            signature.sign(dsc);
            // Save the signed message
            soapMessage.saveChanges();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @WebMethod
    public String signedMethod(String input) {
        // Your SOAP service logic here
        // Sign the SOAP message
        signMessage();

        return "Response: " + input;
    }

    private void signMessage() {
        try {
            // Assuming you have a SOAPMessage object named 'soapMessage'
            // Create a DOMSignContext and specify the private key and location of the resulting XMLSignature's parent element
            DOMSignContext dsc = new DOMSignContext(privateKey, soapMessage.getSOAPPart().getEnvelope());
            // Create a Reference to the enveloped document
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            Reference ref = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
            // Create a SignedInfo
            SignedInfo si = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                            (C14NMethodParameterSpec) null), factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                    Collections.singletonList(ref));
            X509Data xd = kif.newX509Data(Collections.singletonList(cert.getSubjectX500Principal().getName()));
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
            // Create the XMLSignature (but don't sign it yet)
            XMLSignature signature = factory.newXMLSignature(si, ki);
            // Marshal, generate, and sign the enveloped signature
            signature.sign(dsc);
            // Save the signed message
            soapMessage.saveChanges();
            // Now you can use the signed SOAP message as needed
            // For example, send it over a network or log it
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String url = "http://localhost:8080/signed-soap-service";
        Endpoint.publish(url, new SignedSoapService());
        System.out.println("SOAP Service published at: " + url);
    }
}