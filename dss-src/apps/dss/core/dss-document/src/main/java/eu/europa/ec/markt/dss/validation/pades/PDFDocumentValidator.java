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

package eu.europa.ec.markt.dss.validation.pades;

import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelA;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelLTV;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelXL;

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

/**
 * Validation of PDF document.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class PDFDocumentValidator extends SignedDocumentValidator {

   private static final Logger LOG = Logger.getLogger(PDFDocumentValidator.class.getName());

   PDFSignatureService pdfSignatureService;

   /**
    * The default constructor for PDFDocumentValidator.
    */
   public PDFDocumentValidator(DSSDocument document) {
      this.document = document;
      pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
   }

   @Override
   public List<AdvancedSignature> getSignatures() {
      final List<AdvancedSignature> list = new ArrayList<AdvancedSignature>();

      try {
         PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
         pdfSignatureService.validateSignatures(this.document.openStream(), new SignatureValidationCallback() {

            @Override
            public void validate(PdfDict catalog, PdfDict outerCatalog, X509Certificate signingCert, Date signingTime, Certificate[] chain, PdfDict signatureDictionary, PdfSignatureInfo pk) {

               if (signingCert == null) {
                  throw new NotETSICompliantException(MSG.NO_SIGNING_CERTIFICATE);
               }

               if (signingTime == null) {
                  // throw new NotETSICompliantException(MSG.NO_SIGNING_TIME);
               }

               try {
                  if (signatureDictionary != null && !signatureDictionary.hasANameWithValue("Type", "DocTimeStamp")) {
                     list.add(new PAdESSignature(catalog, outerCatalog, signatureDictionary, pk));
                  }
               } catch (Exception ex) {
                  throw new RuntimeException(ex);
               }
            }
         });
      } catch (SignatureException e) {
         throw new RuntimeException(e);
      } catch (IOException e) {
         throw new RuntimeException(e);
      }

      return list;
   }

   @Override
   protected SignatureLevelBES verifyLevelBES(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
      SignatureLevelBES superchecks = super.verifyLevelBES(signature, referenceTime, ctx);
      PAdESSignature pades = (PAdESSignature) signature;

      if (!pades.getSignatureDictionary().hasANameWithValue("SubFilter", "ETSI.CAdES.detached") && !pades.getSignatureDictionary().hasANameWithValue("SubFilter", "ETSI.RFC3161")) {
         LOG.warning("Invalid or missing SubFilter value in the signature dictionary; should be either ETSI.CAdES.detached or ETSI.RFC3161");
      }

      return superchecks;
   }

   @Override
   protected SignatureLevelC verifyLevelC(AdvancedSignature signature, Date referenceTime, ValidationContext ctx, boolean rehash) {
      /* There is no level C in PAdES signature. Return null */
      return null;
   }

   @Override
   protected SignatureLevelX verifyLevelX(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
      /* There is no level X in PAdES signature. Return null */
      return null;
   }

   @Override
   protected SignatureLevelXL verifyLevelXL(AdvancedSignature signature, Date referenceTime, ValidationContext ctx, X509Certificate signingCert) {
      /* There is no level XL in PAdES signature. Return null */
      return null;
   }

   @Override
   protected SignatureLevelA verifyLevelA(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
      /* There is no level A in PAdES signature. Return null */
      return null;
   }

   private boolean checkVriDict(PdfDictionary vriSigDictionary, boolean _vriVerificationresult, PAdESSignature pades, ValidationContext ctx, String hexHash) throws CertificateException, IOException,
            CRLException, OCSPException {

      boolean vriVerificationresult = _vriVerificationresult;

      if (vriSigDictionary == null) {
         LOG.info("Couldn't find the signature VRI identified by " + hexHash + " in the DSS");
         vriVerificationresult = false;
      } else {
         LOG.info("Found the signature VRI identified by " + hexHash + " in the DSS");

         // Verify the certs in the VRI
         PdfArray vricert = vriSigDictionary.getAsArray(new PdfName("Cert"));
         if (vricert != null) {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            List<X509Certificate> certs = new ArrayList<X509Certificate>();
            for (int i = 0; i < vricert.size(); i++) {
               PdfStream stream = vricert.getAsStream(i);
               certs.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(PdfReader.getStreamBytes((PRStream) stream))));
            }
            vriVerificationresult &= isEveryCertificateValuePresent(ctx, certs, pades.getSigningCertificate());
         }

         // Verify the CRLs in the VRI
         PdfArray vricrl = vriSigDictionary.getAsArray(new PdfName("CRL"));
         if (vricrl != null) {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            List<X509CRL> crls = new ArrayList<X509CRL>();
            for (int i = 0; i < vricrl.size(); i++) {
               PdfStream stream = vricrl.getAsStream(i);
               crls.add((X509CRL) factory.generateCRL(new ByteArrayInputStream(PdfReader.getStreamBytes((PRStream) stream))));
            }
            vriVerificationresult &= everyCRLValueOrRefAreThere(ctx, crls);
         }

         // Verify the OCSPs in the VRI
         PdfArray vriocsp = vriSigDictionary.getAsArray(new PdfName("OCSP"));
         if (vriocsp != null) {
            List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
            for (int i = 0; i < vriocsp.size(); i++) {
               PdfStream stream = vriocsp.getAsStream(i);
               ocsps.add((BasicOCSPResp) new OCSPResp(PdfReader.getStreamBytes((PRStream) stream)).getResponseObject());
            }
            vriVerificationresult &= everyOCSPValueOrRefAreThere(ctx, ocsps);
         }
      }
      return vriVerificationresult;
   }

   @Override
   protected SignatureLevelLTV verifyLevelLTV(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      try {

         PAdESSignature pades = (PAdESSignature) signature;
         PdfDict catalog = pades.getOuterCatalog();
         if (catalog == null) {

            catalog = pades.getPdfCatalog();
         }
         // Document Security Store: In the DSS can be stored Validation Related Information (VRI). The DSS contains
         // references to certificates, and the references to OCSP responses and CRLs can be added and can be used to
         // re-verify the certificates.
         PdfDict dss = catalog.getAsDict("DSS");
         if (dss == null) {

            LOG.info("No DSS dictionary!");
            return new SignatureLevelLTV(new Result(ResultStatus.INVALID, "no.dss.dictionary"), null, null);
         }
         LOG.info("DSS dictionary found");
         boolean dssCertsVerificationResult = isEveryCertificateValuePresent(ctx, pades.getExtendedCertificateSource().getCertificates(), pades.getSigningCertificate());
         boolean dssRevocationVerificationResult = true;
         dssRevocationVerificationResult &= everyCRLValueOrRefAreThere(ctx, pades.getCRLs());
         dssRevocationVerificationResult &= everyOCSPValueOrRefAreThere(ctx, pades.getOCSPs());
         boolean vriVerificationresult = true;

         PdfDict pdfDict = pades.getSignatureDictionary();
         if (pdfDict.hasANameWithValue("Type", "Sig")) {

            // Validation Related Information
            PdfDict vri = dss.getAsDict("VRI");
            if (vri == null) {

               LOG.info("No VRI dictionary, this is optional but required by Adobe Acrobat");
               return new SignatureLevelLTV(new Result(ResultStatus.INVALID, "no.vri.dictionary"), null, null);
            }

            // Verify the VRI
            /**
             * The key of each entry in this dictionary is the base-16-encoded (uppercase) SHA1 digest of the signature
             * to which it applies and the value is the Signature VRI dictionary which contains the validation-related
             * information for that signature.
             */
            MessageDigest _md = MessageDigest.getInstance("SHA1");
            Hex.encodeHexString(_md.digest(pdfDict.get("Contents"))).toUpperCase();

         } else if (pdfDict.hasANameWithValue("Type", "DocTimeStamp")) {

            System.out.println("Has DocTimeStamp...");
         } else {

            throw new RuntimeException("Unknown signature dictionary type");
         }
         Result levelReached = null;
         if (dssCertsVerificationResult && dssRevocationVerificationResult) {

            levelReached = new Result(ResultStatus.VALID, null);
         } else {

            levelReached = new Result();
            if (!dssCertsVerificationResult) {

               levelReached.setStatus(ResultStatus.INVALID, "dss.certs.verification.result.error");
            } else if (!dssRevocationVerificationResult) {

               levelReached.setStatus(ResultStatus.INVALID, "dss.revocation.verification.result.error");
            } else if (!vriVerificationresult) {

               levelReached.setStatus(ResultStatus.INVALID, "vri.verification.result.error");
            }
         }
         ResultStatus certificateStatus = dssCertsVerificationResult ? ResultStatus.VALID : ResultStatus.INVALID;
         ResultStatus revocationStatus = dssRevocationVerificationResult ? ResultStatus.VALID : ResultStatus.INVALID;
         return new SignatureLevelLTV(levelReached, new Result(certificateStatus, null), new Result(revocationStatus, null));
      } catch (Exception e) {

         throw new RuntimeException(e);
      }
   }
}
