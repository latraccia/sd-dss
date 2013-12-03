package eu.europa.ec.markt.dss.signature.xades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifyingPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ReferenceType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.TransformType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.TransformsType;

/**
 * 
 * This class handles the specifics of the enveloped XML signature
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
class EnvelopedSignatureBuilder extends SignatureBuilder {

   /**
    * The default constructor for EnvelopedSignatureBuilder. The enveloped signature uses by default the exclusive
    * method of canonicalisation.
    * 
    * @param params The set of parameters relating to the structure and process of the creation or extension of the
    *           electronic signature.
    * @param origDoc The original document to sign.
    */
   public EnvelopedSignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

      super(params, origDoc);
      signedInfoCanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
      reference2CanonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
   }

   /**
    * This method creates the qualifying properties with specific parameters of enveloped form of signature.
    * 
    * @throws DSSException
    */
   @Override
   protected QualifyingPropertiesType createQualifyingProperties() throws DSSException {

      return createXAdESQualifyingProperties("#xml_ref_id", "text/xml");
   }

   /**
    * This method creates the first reference (this is a reference to the file to be signed) witch is specific for each
    * form of signature. Here, the value of the URI is set to http://www.w3.org/TR/1999/REC-xpath-19991116 (XPath
    * recommendation) which means that an XPath-expression must be used to select a defined subset of the document tree.
    */
   @Override
   protected ReferenceType createReference1() throws DSSException {

      ReferenceType referenceT1 = xmlDSigFactory.createReferenceType();
      DigestMethodType digestMethodT = xmlDSigFactory.createDigestMethodType();
      digestMethodT.setAlgorithm(params.getDigestAlgorithm().getXmlId());
      referenceT1.setDigestMethod(digestMethodT);
      TransformsType transformsT = xmlDSigFactory.createTransformsType();
      List<TransformType> transforms = transformsT.getTransform();
      transforms.add(createTransform(CanonicalizationMethod.ENVELOPED, ""));
      // sign the document but no the <ds:Signature> segment
      transforms.add(createTransform(signedInfoCanonicalizationMethod, ""));
      // For double signatures
      transforms.add(createTransform("http://www.w3.org/TR/1999/REC-xpath-19991116", "not(ancestor-or-self::ds:Signature)"));

      referenceT1.setTransforms(transformsT);
      referenceT1.setURI("");
      referenceT1.setId("xml_ref_id");

      try {

         Canonicalizer c14n = Canonicalizer.getInstance(signedInfoCanonicalizationMethod);
         // We remove existing signatures
         // LOG.info("====> XYZ: " + origDoc.getName());
         final Document domDoc = DSSXMLUtils.buildDOM(origDoc);
         final NodeList signatureNodeList = domDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
         for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

            final Element signatureDOM = (Element) signatureNodeList.item(ii);
            signatureDOM.getParentNode().removeChild(signatureDOM);
         }
         byte[] cannonicalized = c14n.canonicalizeSubtree(domDoc);
         if (LOG.isLoggable(Level.FINE)) LOG.fine("Canonicalisation method  -->" + signedInfoCanonicalizationMethod);
         if (LOG.isLoggable(Level.FINE)) LOG.fine("Canonicalised REF_1      --> " + new String(cannonicalized));
         referenceT1.setDigestValue(createDigest(cannonicalized));
         return referenceT1;
      } catch (InvalidCanonicalizerException e) {
         throw new DSSException(e);
      } catch (CanonicalizationException e) {
         throw new DSSException(e);
      } catch (IOException e) {
         throw new DSSException(e);
      } catch (SAXException e) {
         throw new DSSException(e);
      } catch (ParserConfigurationException e) {
         throw new DSSException(e);
      }
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

         Document origDocDom = DSSXMLUtils.buildDOM(origDoc);

         byte[] signatureBytes = normaliseSignatureNS(signature);
         Document signatureDom = DSSXMLUtils.buildDOM(signatureBytes);

         Node signatureElement = signatureDom.getFirstChild();
         Node copiedNode = origDocDom.importNode(signatureElement, true);
         origDocDom.getDocumentElement().appendChild(copiedNode);

         ByteArrayOutputStream outputDoc = new ByteArrayOutputStream();
         Result output = new StreamResult(outputDoc);
         Transformer xformer = TransformerFactory.newInstance().newTransformer();
         Source source = new DOMSource(origDocDom);
         xformer.transform(source, output);
         // IOUtils.write(outputDoc.toByteArray(), System.out);
         return new InMemoryDocument(outputDoc.toByteArray());
      } catch (Exception e) {

         throw new DSSException(e);
      } finally {

      }
   }
}