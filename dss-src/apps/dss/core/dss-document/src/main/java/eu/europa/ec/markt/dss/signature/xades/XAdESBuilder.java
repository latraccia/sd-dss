package eu.europa.ec.markt.dss.signature.xades;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDType;
import eu.europa.ec.markt.tsl.jaxb.xades.DigestAlgAndValueType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectFactory;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.SignatureType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.X509IssuerSerialType;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class XAdESBuilder {

   protected static final Logger LOG = Logger.getLogger(XAdESBuilder.class.getName());

   /*
    * A reference to the JAXB marshaller that will convert the JAXB object model to the XML string.
    */
   protected static Marshaller marshaller;

   /*
    * A reference to the JAXB unmarshaller that deserialising XML data into Java content trees (JAXB).
    */
   protected static Unmarshaller unmarshaller;

   /*
    * This variable is a reference to the set of parameters relating to the structure and process of the creation or
    * extension of the electronic signature.
    */
   protected SignatureParameters params;

   static final String XADES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

   /*
    * A reference to the JAXB factory that can build different objects constituting the basic signature (XMLDSIG).
    */
   protected static eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory xmlDSigFactory = new eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory();

   /*
    * A reference to the JAXB factory that can build different objects constituting the XAdES signature.
    */
   protected static final ObjectFactory xadesFactory = new ObjectFactory();

   /*
    * A reference to the JAXB factory that can build different objects constituting the XAdES 141 signature.
    */
   protected static final eu.europa.ec.markt.jaxb.xades141.ObjectFactory xades141Factory = new eu.europa.ec.markt.jaxb.xades141.ObjectFactory();

   /**
    * A reference to the factory that creates new javax.xml.datatype Objects that map XML to/from Java Objects.<br>
    * Used to manage XMLGregorianCalendar
    */
   protected static DatatypeFactory _dataFactory;

   /*
    * This object is used to create a new DOM document
    */
   protected static DocumentBuilder documentBuilder;

   /*
    * This static block of code initialises the static variables with JAXB objects. The NamespacePrefixMapperImpl class
    * is also instantiated and its instance is used to manage name spaces.
    */
   static {

      try {

         LOG.setLevel(Level.FINE); // !!

         // Initialisation of JAXB static objects
         /*
          * A reference to the JAXB factory that can build different objects constituting the XAdES specific signature.
          */
         final JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
         marshaller = jaxbContext.createMarshaller();
         unmarshaller = jaxbContext.createUnmarshaller();
         // marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper", new NamespacePrefixMapperImpl());
         // The line below allows to format the generated XML.
         // marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         // marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);

         _dataFactory = DatatypeFactory.newInstance();

         // Initialisation of DOM static objects
         DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
         dfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
         dfactory.setNamespaceAware(true);
         // dfactory.setValidating(true);
         documentBuilder = dfactory.newDocumentBuilder();
      } catch (DatatypeConfigurationException e) {

         // TODO: We must define the common way to manage the exceptions
         throw new DSSException(e);
      } catch (JAXBException e) {

         // TODO: We must define the common way to manage the exceptions
         throw new DSSException(e);
      } catch (ParserConfigurationException e) {

         // TODO: We must define the common way to manage the exceptions
         throw new DSSException(e);
      }
   }

   /**
    * The reference to the signature JAXB Object. Is initialised when unmarshal
    */
   SignatureType signatureT;

   /**
    * 
    * @param data
    * @param digestAlgorithm
    * @return
    * @throws DSSException
    */
   static DigestAlgAndValueType getDigestAlgAndValue(byte[] data, DigestAlgorithm digestAlgorithm) throws DSSException {

      DigestAlgAndValueType digestAlgAndValue = xadesFactory.createDigestAlgAndValueType();

      DigestMethodType digestMethod = xmlDSigFactory.createDigestMethodType();
      digestAlgAndValue.setDigestMethod(digestMethod);
      digestMethod.setAlgorithm(digestAlgorithm.getXmlId());

      MessageDigest messageDigest;
      try {

         messageDigest = MessageDigest.getInstance(digestAlgorithm.getName());
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException("message digest algo error: " + e.getMessage(), e);
      }
      digestAlgAndValue.setDigestValue(messageDigest.digest(data));

      return digestAlgAndValue;
   }

   /**
    * Gives back the JAXB CertID data structure.
    * 
    * @param certificate
    * @param xadesObjectFactory
    * @param xmldsigObjectFactory
    * @param digestAlgorithm
    * @return
    * @throws DSSException
    */
   static CertIDType getCertID(X509Certificate certificate, DigestAlgorithm digestAlgorithm) throws DSSException {

      CertIDType certId = xadesFactory.createCertIDType();

      X509IssuerSerialType issuerSerial = xmlDSigFactory.createX509IssuerSerialType();
      issuerSerial.setX509IssuerName(certificate.getIssuerX500Principal().getName());
      issuerSerial.setX509SerialNumber(certificate.getSerialNumber());
      certId.setIssuerSerial(issuerSerial);
      byte[] encodedCertificate;
      try {

         encodedCertificate = certificate.getEncoded();
      } catch (CertificateEncodingException e) {

         throw new DSSException("certificate encoding error: " + e.getMessage(), e);
      }
      DigestAlgAndValueType certDigest = getDigestAlgAndValue(encodedCertificate, digestAlgorithm);
      certId.setCertDigest(certDigest);
      return certId;
   }

   static List<Object> getExistingTags(List<Object> refs, String tag) {

      List<Object> existingTags = new ArrayList<Object>();
      for (Object object : refs) {

         if (!((JAXBElement<?>) object).getName().getLocalPart().equals(tag)) {

            existingTags.add(object);
         }
      }
      return existingTags;
   }

   /**
    * Unmarshal XML data from the specified InputStream and return the resulting content tree.
    * 
    * @param input
    * @return
    * @throws JAXBException
    */
   protected SignatureType unmarsal(final InputStream input) throws JAXBException {

      @SuppressWarnings("unchecked")
      JAXBElement<SignatureType> jaxbElement = (JAXBElement<SignatureType>) unmarshaller.unmarshal(input);
      return jaxbElement.getValue();
   }

   /**
    * Unmarshal global XML data from the specified DOM tree and return the resulting content tree.
    * 
    * @param element
    * @return
    * @throws JAXBException
    */
   @SuppressWarnings("unchecked")
   protected SignatureType unmarsal(final Element element) throws JAXBException {

      signatureT = ((JAXBElement<SignatureType>) unmarshaller.unmarshal(element)).getValue();
      return signatureT;
   }

   /**
    * Marshal the content tree rooted at jaxbElement into a DOM tree.
    * 
    * @param signatureT
    * @param signatureDOM
    * @throws DSSException
    */
   protected void marshal(JAXBElement<?> jaxbObject, Node domNode) throws DSSException {

      try {

         marshaller.marshal(jaxbObject, domNode);
      } catch (JAXBException e) {

         throw new DSSException(e);
      }
   }
}
