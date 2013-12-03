package eu.europa.ec.markt.dss.signature.xades;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectType;

import org.w3c.dom.Element;

import javax.xml.bind.JAXBException;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public abstract class ExtensionBuilder extends XAdESBuilder {

   /*
    * Static object to build the X509 certificates
    */
   protected static CertificateFactory certificateFactory;

   static {

      if (certificateFactory == null) {

         try {

            certificateFactory = CertificateFactory.getInstance("X509");
         } catch (CertificateException e) {

            throw new RuntimeException("Static initialiser", e);
         }
      }
   }

   /*
    * This object allows to access DOM signature representation using XPATH
    */
   protected XAdESSignature xadesSignature;

   /**
    * returns or creates (if it does not exist) the ObjectType JAXB object.
    * 
    * @param signatureT
    * @return
    * @throws DSSException
    */
   protected void ensureObject() throws DSSException {

      Element parentElement = xadesSignature.getSignatureElement();
      Element element = xadesSignature.getObject();
      if (element == null) {

         ObjectType object = xmlDSigFactory.createObjectType();
         marshal(xmlDSigFactory.createObject(object), parentElement);
      }
   }

   /**
    * returns or creates (if it does not exist) the QualifyingPropertiesType JAXB object.
    * 
    * @param objectT
    * @return
    * @throws DSSException
    */
   protected void ensureQualifyingProperties() throws DSSException {

      Element parentElement = xadesSignature.getObject();
      Element element = xadesSignature.getQualifyingProperties();
      if (element == null) {

         marshal(xadesFactory.createQualifyingProperties(xadesFactory.createQualifyingPropertiesType()), parentElement);
      }
   }

   /**
    * returns or creates (if it does not exist) the UnsignedPropertiesType JAXB object.
    * 
    * @param unsignedPropertiesNode
    * @return
    * @throws JAXBException
    * @throws DSSException
    */
   protected void ensureUnsignedProperties() throws JAXBException, DSSException {

      Element parentElement = xadesSignature.getQualifyingProperties();
      Element element = xadesSignature.getUnsignedProperties();
      if (element == null) {

         marshal(xadesFactory.createUnsignedProperties(xadesFactory.createUnsignedPropertiesType()), parentElement);
      }
   }

   /**
    * returns or creates (if it does not exist) the UnsignedSignaturePropertiesType JAXB object.
    * 
    * @param uPropertiesT
    * @return
    * @throws DSSException
    */
   protected void ensureUnsignedSignatureProperties() throws DSSException {

      Element parentElement = xadesSignature.getUnsignedProperties();
      Element element = xadesSignature.getUnsignedSignatureProperties();
      if (element == null) {

         marshal(xadesFactory.createUnsignedSignatureProperties(xadesFactory.createUnsignedSignaturePropertiesType()), parentElement);
      }
   }

   /**
    * To be implemented a mechanism to determine whether it is possible to add the extension. In some cases it is
    * necessary to remove the existing extensions. This mechanism can be controlled by a flag (SigantureParameters).<br>
    * When the signature includes already an -A extension the fact to add a -T extension will temper the -A extension.
    * 
    * @return
    */
   protected boolean canAddExtension() {

      // TODO: (Bob)
      return true;
   }
}
