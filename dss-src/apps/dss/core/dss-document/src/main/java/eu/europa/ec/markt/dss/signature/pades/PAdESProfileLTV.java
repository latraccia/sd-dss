/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pades;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfReader;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;
import eu.europa.ec.markt.dss.signature.pdf.PdfWriter;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

/**
 * Extend a PAdES extension up to LTV.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class PAdESProfileLTV implements SignatureExtension {

   private PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();

   private CertificateVerifier certificateVerifier;

   private Map<X509Certificate, PdfStream> certsRefs = new HashMap<X509Certificate, PdfStream>();
   private Map<X509CRL, PdfStream> crlRefs = new HashMap<X509CRL, PdfStream>();
   private Map<BasicOCSPResp, PdfStream> ocspRefs = new HashMap<BasicOCSPResp, PdfStream>();

   private TSPSource tspSource;

   class LTVSignatureValidationCallback implements SignatureValidationCallback {

      private PdfWriter stamper;

      private PdfArray certsArray = PdfObjFactory.getInstance().newArray();

      private PdfArray ocspsArray = PdfObjFactory.getInstance().newArray();

      private PdfArray crlsArray = PdfObjFactory.getInstance().newArray();

      private ValidationContext validationContext;

      private byte[] signatureBlock;

      public LTVSignatureValidationCallback(PdfWriter stamper) {

         this.stamper = stamper;
      }

      @Override
      public void validate(PdfDict catalog, PdfDict outerCatalog, X509Certificate signingCert, Date signingDate, Certificate[] certs, PdfDict signatureDictionary, PdfSignatureInfo pk) {

         if (signingCert == null) {
            throw new NotETSICompliantException(MSG.NO_SIGNING_CERTIFICATE);
         }

         if (signingDate == null) {
            throw new NotETSICompliantException(MSG.NO_SIGNING_TIME);
         }

         try {

            this.signatureBlock = signatureDictionary.get("Contents");

            CAdESSignature cades = new CAdESSignature(signatureBlock);
            final ValidationContext ctx = certificateVerifier.validateCertificate(signingCert, signingDate, cades.getCertificateSource(), null, null);
            if (cades.getSignatureTimestamps() != null) {
               for (TimestampToken tstoken : cades.getSignatureTimestamps()) {
                  ctx.validateTimestamp(tstoken, cades.getCertificateSource(), null, null);
               }
            }

            for (BasicOCSPResp ocsp : ctx.getNeededOCSPResp()) {
               try {
                  PdfStream stream = PdfObjFactory.getInstance().newStream(OCSPUtils.fromBasicToResp(ocsp).getEncoded());
                  stamper.addToArray(ocspsArray, stream);
                  ocspRefs.put(ocsp, stream);
               } catch (IOException e) {
                  throw new RuntimeException(e);
               }
            }

            for (X509CRL crl : ctx.getNeededCRL()) {
               try {
                  PdfStream stream = PdfObjFactory.getInstance().newStream(crl.getEncoded());
                  stamper.addToArray(crlsArray, stream);
                  crlRefs.put(crl, stream);
               } catch (CRLException e) {
                  throw new RuntimeException(e);
               } catch (IOException e) {
                  throw new RuntimeException(e);
               }
            }

            for (CertificateAndContext cert : ctx.getNeededCertificates()) {
               try {
                  PdfStream stream = PdfObjFactory.getInstance().newStream(cert.getCertificate().getEncoded());
                  stamper.addToArray(certsArray, stream);
                  certsRefs.put(cert.getCertificate(), stream);
               } catch (CertificateEncodingException e) {
                  throw new RuntimeException(e);
               } catch (IOException e) {
                  throw new RuntimeException(e);
               }
            }
         } catch (CMSException e) {
            throw new RuntimeException(e);
         } catch (IOException e) {
            throw new RuntimeException(e);
         }
      }

      /**
       * @return the certsArray
       */
      public PdfArray getCertsArray() {

         return certsArray;
      }

      /**
       * @return the crlsArray
       */
      public PdfArray getCrlsArray() {

         return crlsArray;
      }

      /**
       * @return the ocspsArray
       */
      public PdfArray getOcspsArray() {

         return ocspsArray;
      }

      /**
       * @return the signatureBlock
       */
      public byte[] getSignatureBlock() {

         return signatureBlock;
      }

      /**
       * @return the validationContext
       */
      public ValidationContext getValidationContext() {

         return validationContext;
      }
   }

   /**
    * @param tspSource the tspSource to set
    */
   public void setTspSource(TSPSource tspSource) {

      this.tspSource = tspSource;
   }

   /**
    * @param certificateVerifier the certificateVerifier to set
    */
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   private void buildVRIDict(PdfWriter stamper, BasicOCSPResp ocsp, PdfDict vriDictionary) throws IOException, NoSuchAlgorithmException {

      PdfDict ocspVriDictionary = PdfObjFactory.getInstance().newDict();
      stamper.addToDict(ocspVriDictionary, "TU", Calendar.getInstance(TimeZone.getTimeZone("GMT")));

      MessageDigest md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
      String hexHash = Hex.encodeHexString(md.digest(ocsp.getSignature())).toUpperCase();

      stamper.addToDict(ocspVriDictionary, hexHash, vriDictionary);
   }

   private void buildVRIDict(PdfWriter stamper, X509CRL crl, PdfDict vriDictionary) throws IOException, NoSuchAlgorithmException {

      PdfDict crlVriDictionary = PdfObjFactory.getInstance().newDict();
      stamper.addToDict(crlVriDictionary, "TU", Calendar.getInstance(TimeZone.getTimeZone("GMT")));
      // Other objects?

      MessageDigest md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
      String hexHash = Hex.encodeHexString(md.digest(crl.getSignature())).toUpperCase();

      stamper.addToDict(vriDictionary, hexHash, crlVriDictionary);
   }

   private void integrateCRL(LTVSignatureValidationCallback callback, PdfWriter stamper, PdfDict dssDictionary, PdfDict sigVriDictionary, PdfDict vriDictionary) throws IOException {

      // FIXME: (Bob: 2013.08.19) If there is no CRLs then the validation is impossible! This must be fixed!
      PdfArray crlArray = callback.getCrlsArray();
      if (crlArray.size() > 0) {
         // Reference in the DSS dictionary
         stamper.addToDict(dssDictionary, "CRLs", crlArray);

         // Array in the signature's VRI dictionary
         stamper.addToDict(sigVriDictionary, "CRL", crlArray);

         // Build and reference a VRI dictionary for each CRL
         for (X509CRL crl : crlRefs.keySet()) {
            try {
               buildVRIDict(stamper, crl, vriDictionary);
            } catch (NoSuchAlgorithmException e) {
               throw new RuntimeException();
            }
         }
      }
   }

   private void integrateOCSP(LTVSignatureValidationCallback callback, PdfWriter stamper, PdfDict dssDictionary, PdfDict sigVriDictionary, PdfDict vriDictionary) throws IOException {

      // FIXME: (Bob: 2013.08.19) If there is no OCSPs then the validation is impossible! This must be fixed!
      PdfArray ocspsArray = callback.getOcspsArray();
      if (ocspsArray.size() > 0) {
         // Reference in the DSS dictionary
         stamper.addToDict(dssDictionary, "OCSPs", ocspsArray);

         // Array in the signature's VRI dictionary

         stamper.addToDict(sigVriDictionary, "OCSP", ocspsArray);

         // Build and reference a VRI dictionary for each OCSP response
         for (BasicOCSPResp ocsp : ocspRefs.keySet()) {
            try {
               buildVRIDict(stamper, ocsp, vriDictionary);
            } catch (NoSuchAlgorithmException e) {
               throw new RuntimeException();
            }
         }
      }
   }

   /**
    * 
    * @param document
    * @param originalData
    * @param params
    * @return
    * @throws IOException
    */
   public DSSDocument extendSignatures(DSSDocument document, DSSDocument originalData, SignatureParameters params) throws IOException {

      /**
       * TODO 20130819 (Bob)To be investigated why originalData is not used. Example in test case:
       * /dss-document/src/test/java/functional/testing/TC_DSS_224Test.java this parameter is used. This file was
       * compared with revision 1137 and this parameter has not been used either.
       */

      try {

         PdfObjFactory factory = PdfObjFactory.getInstance();
         final PdfReader reader = factory.newReader(document.openStream());
         final ByteArrayOutputStream output = new ByteArrayOutputStream();
         final PdfWriter stamper = factory.newWriter(reader, output);

         LTVSignatureValidationCallback callback = new LTVSignatureValidationCallback(stamper);
         pdfSignatureService.validateSignatures(document.openStream(), callback);

         PdfDict dssDictionary = factory.newDict("DSS");
         PdfDict vriDictionary = factory.newDict("VRI");

         PdfDict sigVriDictionary = factory.newDict();

         integrateCRL(callback, stamper, dssDictionary, sigVriDictionary, sigVriDictionary);

         integrateOCSP(callback, stamper, dssDictionary, sigVriDictionary, sigVriDictionary);

         /**
          * Add the signature's VRI dictionary, hashing the signature block from the callback method.<br>
          * The key of each entry in this dictionary is the base-16-encoded (uppercase) SHA1 digest of the signature to
          * which it applies and the value is the Signature VRI dictionary which contains the validation-related
          * information for that signature.
          */
         MessageDigest _md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
         String hexHash = Hex.encodeHexString(_md.digest(callback.getSignatureBlock())).toUpperCase();

         stamper.addToDict(vriDictionary, hexHash, sigVriDictionary);

         stamper.addToDict(dssDictionary, "VRI", vriDictionary);

         stamper.addToDict(dssDictionary, "Certs", callback.getCertsArray());

         stamper.addToDict(reader.getCatalog(), "DSS", dssDictionary);

         stamper.close();
         output.close();

         DSSDocument extendedDocument = new InMemoryDocument(output.toByteArray());

         ByteArrayOutputStream ltvDoc = new ByteArrayOutputStream();

         PDFSignatureService service = factory.newTimestampSignatureService();
         byte[] digest = service.digest(extendedDocument.openStream(), params);
         TimeStampResponse tsToken = tspSource.getTimeStampResponse(params.getDigestAlgorithm(), digest);
         service.sign(extendedDocument.openStream(), tsToken.getTimeStampToken().getEncoded(), ltvDoc, params);

         return new InMemoryDocument(ltvDoc.toByteArray());

      } catch (SignatureException e) {
         throw new RuntimeException(e);
      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException(e);
      }
   }

   @Override
   public DSSDocument extendSignatures(DSSDocument document, SignatureParameters params) throws DSSException {

      try {

         return extendSignatures(document, null, params);
      } catch (IOException e) {

         throw new DSSException(e);
      }
   }

   @Override
   @Deprecated
   public DSSDocument extendSignature(Object signatureId, DSSDocument document, SignatureParameters params) throws IOException {

      return null;
   }

}
