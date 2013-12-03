package eu.europa.ec.markt.dss.applet.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.asic.ASiCXMLSignatureService;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.signature.pades.PAdESServiceV2;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation.TrustedListCertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public final class SigningUtils {

   /**
    * 
    * @param signedFile
    * @param originalFile
    * @param parameters
    * @param tspSource
    * @param certificateVerifier
    * @return
    * @throws IOException
    */
   public static DSSDocument extendDocument(final File signedFile, final File originalFile, final SignatureParameters parameters, final TSPSource tspSource,
            final TrustedListCertificateVerifier certificateVerifier) throws IOException {

      final DSSDocument signedDocument = new FileDocument(signedFile);
      final DSSDocument originalDocument = new FileDocument(originalFile);
      parameters.setOriginalDocument(originalDocument);
      final DocumentSignatureService signatureService = getSignatureService(parameters.getSignatureFormat(), tspSource, certificateVerifier);
      return signatureService.extendDocument(signedDocument, parameters);
   }

   private static DocumentSignatureService getSignatureService(final SignatureFormat signatureFormat, final TSPSource tspSource, final TrustedListCertificateVerifier certificateVerifier) {

      final String format = signatureFormat.name().toUpperCase();

      if (format.startsWith("XADES")) {
         final XAdESService service = new XAdESService();
         service.setCertificateVerifier(certificateVerifier);
         service.setTspSource(tspSource);
         return service;
      }
      if (format.startsWith("CADES")) {
         final CAdESService service = new CAdESService();
         service.setCertificateVerifier(certificateVerifier);
         service.setTspSource(tspSource);
         return service;
      }
      if (format.toUpperCase().startsWith("PADES")) {
         final PAdESServiceV2 service = new PAdESServiceV2();
         service.setCertificateVerifier(certificateVerifier);
         service.setTspSource(tspSource);
         return service;
      }
      if (format.startsWith("ASIC")) {
         final ASiCXMLSignatureService service = new ASiCXMLSignatureService();
         service.setCertificateVerifier(certificateVerifier);
         service.setTspSource(tspSource);
         return service;
      }
      // FIXME
      throw new RuntimeException("Cannot create Signature service");

   }

   /**
    * 
    * @param file
    * @param parameters
    * @param tspSource
    * @param certificateVerifier
    * @param tokenConnection
    * @param privateKey
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws DSSException
    */
   public static DSSDocument signDocument(final File file, final SignatureParameters parameters, final TSPSource tspSource, final TrustedListCertificateVerifier certificateVerifier,
            final SignatureTokenConnection tokenConnection, final DSSPrivateKeyEntry privateKey) throws IOException, NoSuchAlgorithmException, DSSException {

      final DSSDocument document = new FileDocument(file);
      final DocumentSignatureService signatureService = getSignatureService(parameters.getSignatureFormat(), tspSource, certificateVerifier);
      try {
         if (signatureService instanceof CAdESService && SignaturePackaging.ENVELOPING == parameters.getSignaturePackaging()) {
            final CMSSignedData cmsData = new CMSSignedData(document.openStream());

            if (cmsData != null && cmsData.getSignedContent() != null && cmsData.getSignedContent().getContent() != null) {
               final ByteArrayOutputStream buf = new ByteArrayOutputStream();
               cmsData.getSignedContent().write(buf);
               final DSSDocument contentInCMS = new InMemoryDocument(buf.toByteArray());
               final byte[] signatureValue = tokenConnection.sign(signatureService.toBeSigned(contentInCMS, parameters), DigestAlgorithm.SHA1, privateKey);
               final CAdESService cadesService = (CAdESService) signatureService;
               return cadesService.addASignatureToDocument(document, parameters, signatureValue);
            }
         }
      } catch (final CMSException e) {
         // Ignore
      }

      InputStream inputStream = null;
      try {
         inputStream = signatureService.toBeSigned(document, parameters);
         final byte[] signatureValue = tokenConnection.sign(inputStream, parameters.getDigestAlgorithm(), privateKey);
         return signatureService.signDocument(document, parameters, signatureValue);
      } finally {
         DSSUtils.closeQuietly(inputStream);
      }

   }

   private SigningUtils() {

   }

}
