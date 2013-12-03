package eu.europa.ec.markt.dss.signature.xades;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifyingPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ReferenceType;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.transform.TransformerFactoryConfigurationError;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * 
 * This class handles the specifics of the detached XML signature.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
class DetachedSignatureBuilder extends SignatureBuilder {

   // private static final Logger LOG = Logger.getLogger(DetachedSignatureBuilder.class.getName());

   /**
    * The file name of the file to sign
    */
   private final String fileName;

   /**
    * 
    * The default constructor for DetachedSignatureBuilder.<br>
    * The detached signature uses by default the exclusive method of canonicalization.
    * 
    * @param params The set of parameters relating to the structure and process of the creation or extension of the
    *           electronic signature.
    * @param origDoc The original document to sign.
    */
   public DetachedSignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

      super(params, origDoc);
      signedInfoCanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
      reference2CanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
      this.fileName = origDoc.getName();
   }

   /**
    * This method creates the qualifying properties with specific parameters of detached form of signature.
    * 
    * @throws DSSException
    */
   @Override
   protected QualifyingPropertiesType createQualifyingProperties() throws DSSException {

      return createXAdESQualifyingProperties("#detached-ref-id", "text/plain");
   }

   /**
    * This method creates the first reference (this is a reference to the file to sign) witch is specific for each form
    * of signature. Here, the value of the URI is the name of the file to sign or if the information is not available
    * the URI will use the default value: "detached-file".
    * 
    * @return JAXB ReferenceType object
    * @throws NoSuchAlgorithmException
    * @throws IOException
    */
   @Override
   protected ReferenceType createReference1() throws DSSException {

      ReferenceType referenceT1 = xmlDSigFactory.createReferenceType();
      DigestMethodType digestMethodT = xmlDSigFactory.createDigestMethodType();
      digestMethodT.setAlgorithm(params.getDigestAlgorithm().getXmlId());
      referenceT1.setDigestMethod(digestMethodT);

      // TODO (Bob): To check if we can create this signature without the file name
      referenceT1.setURI(fileName != null ? fileName : "detached-file");
      referenceT1.setId("detached-ref-id");

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
      signatureT.getSignatureValue().setValue(DSSSignatureUtils.convertToXmlDSig(params.getEncryptionAlgorithm(), signatureValue));
      try {

         byte[] signatureBytes = normaliseSignatureNS(signature);
         return new InMemoryDocument(signatureBytes);
      } catch (TransformerFactoryConfigurationError e) {
         throw new DSSException(e);
      }
   }
}