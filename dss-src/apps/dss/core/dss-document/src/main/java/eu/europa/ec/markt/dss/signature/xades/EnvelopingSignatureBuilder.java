package eu.europa.ec.markt.dss.signature.xades;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifyingPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ReferenceType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.TransformType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.TransformsType;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.transform.TransformerFactoryConfigurationError;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * 
 * This class handles the specifics of the enveloping XML signature
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
class EnvelopingSignatureBuilder extends SignatureBuilder {

   /**
    * 
    * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
    * method of canonicalisation.
    * 
    * @param params The set of parameters relating to the structure and process of the creation or extension of the
    *           electronic signature.
    * @param origDoc The original document to sign.
    */
   public EnvelopingSignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

      super(params, origDoc);
      signedInfoCanonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
      reference2CanonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
   }

   /**
    * This method creates the qualifying properties with specific parameters of enveloped form of signature.
    * 
    * @throws DSSException
    */
   @Override
   protected QualifyingPropertiesType createQualifyingProperties() throws DSSException {

      return createXAdESQualifyingProperties("#signed-data-ref", "text/plain");
   }

   /**
    * This method creates the first reference (this is a reference to the file to sign) witch is specific for each form
    * of signature. Here, the value of the URI is an unique identifier to the base64 encoded data (file). The data are
    * included in the signature XML.
    * 
    * @throws IOException
    * @throws NoSuchAlgorithmException
    */
   @Override
   protected ReferenceType createReference1() throws DSSException {

      ReferenceType referenceT1 = xmlDSigFactory.createReferenceType();
      DigestMethodType digestMethodT = xmlDSigFactory.createDigestMethodType();
      digestMethodT.setAlgorithm(params.getDigestAlgorithm().getXmlId());
      referenceT1.setDigestMethod(digestMethodT);
      TransformsType transformsT = xmlDSigFactory.createTransformsType();
      List<TransformType> transforms = transformsT.getTransform();
      transforms.add(createTransform(CanonicalizationMethod.BASE64, ""));
      referenceT1.setTransforms(transformsT);
      referenceT1.setURI("#signed-data-" + params.getDeterministicId());
      referenceT1.setId("signed-data-ref");
      referenceT1.setType("http://www.w3.org/2000/09/xmldsig#Object");

      referenceT1.setDigestValue(createDigest(origDoc.getBytes()));

      return referenceT1;
   }

   /**
    * Adds signature value to the signature and returns XML signature (InMemoryDocument)
    * 
    * @param signatureValue
    * @return
    * @throws DSSException
    */
   @Override
   public DSSDocument signDocument(final byte[] signatureValue) throws DSSException {

      if (!built) {

         build();
      }
      try {

         signatureT.getSignatureValue().setValue(DSSSignatureUtils.convertToXmlDSig(params.getEncryptionAlgorithm(), signatureValue));

         ObjectType objectT = xmlDSigFactory.createObjectType();
         objectT.setId("signed-data-" + params.getDeterministicId());
         String encodedData = DSSUtils.base64Encode(origDoc.getBytes());
         objectT.getContent().add(encodedData);

         signatureT.getObject().add(objectT);

         byte[] signatureBytes = normaliseSignatureNS(signature);
         return new InMemoryDocument(signatureBytes);
      } catch (TransformerFactoryConfigurationError e) {
         throw new DSSException(e);
      }
   }
}