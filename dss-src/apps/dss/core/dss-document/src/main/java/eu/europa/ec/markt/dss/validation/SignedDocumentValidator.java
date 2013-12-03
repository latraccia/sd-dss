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

package eu.europa.ec.markt.dss.validation;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.ProfileException;
import eu.europa.ec.markt.dss.validation.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation.cades.CMSDocumentValidator;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation.report.CertPathRevocationAnalysis;
import eu.europa.ec.markt.dss.validation.report.QCStatementInformation;
import eu.europa.ec.markt.dss.validation.report.QualificationsVerification;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;
import eu.europa.ec.markt.dss.validation.report.SignatureInformation;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelA;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelAnalysis;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelEPES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelLTV;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelT;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelXL;
import eu.europa.ec.markt.dss.validation.report.SignatureVerification;
import eu.europa.ec.markt.dss.validation.report.TimeInformation;
import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;
import eu.europa.ec.markt.dss.validation.report.TrustedListInformation;
import eu.europa.ec.markt.dss.validation.report.ValidationReport;
import eu.europa.ec.markt.dss.validation.tsl.Condition;
import eu.europa.ec.markt.dss.validation.tsl.PolicyIdCondition;
import eu.europa.ec.markt.dss.validation.tsl.QcStatementCondition;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;
import eu.europa.ec.markt.dss.validation.xades.XMLDocumentValidator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Validate the signed document
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public abstract class SignedDocumentValidator {

   private static final Logger LOG = Logger.getLogger(SignedDocumentValidator.class.getName());

   private static final String SVC_INFO = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/";

   protected DSSDocument document;

   /*
    * In case of ASiC, this is the signature
    */
   public DSSDocument getDocument() {

      return document;
   }

   protected DSSDocument externalContent;

   private CertificateVerifier certificateVerifier;

   private final Condition qcp = new PolicyIdCondition("0.4.0.1456.1.2");

   private final Condition qcpplus = new PolicyIdCondition("0.4.0.1456.1.1");

   private final Condition qccompliance = new QcStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);

   private final Condition qcsscd = new QcStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD);

   private static final String MIMETYPE = "mimetype";

   // private static final String MIMETYPE_ASIC_S = "application/vnd.etsi.asic-s+zip";
   private static final String PATTERN_SIGNATURES_XML = "META-INF/(.*)(?i)signature(.*).xml";

   private static final String PATTERN_SIGNATURES_P7S = "META-INF/(.*)(?i)signature(.*).p7s";

   /**
    * Guess the document format and return an appropriate document
    * 
    * @param document
    * @return
    */
   public static SignedDocumentValidator fromDocument(DSSDocument document) throws IOException {

      InputStream input = null;
      try {

         if (document.getName() != null && document.getName().toLowerCase().endsWith(".xml")) {

            try {

               return new XMLDocumentValidator(document);
            } catch (ParserConfigurationException e) {
               throw new IOException("Not a valid XML");
            } catch (SAXException e) {
               throw new IOException("Not a valid XML");
            }
         }

         input = new BufferedInputStream(document.openStream());
         input.mark(5);
         byte[] preamble = new byte[5];
         int read = input.read(preamble);
         input.reset();
         if (read < 5) {

            throw new RuntimeException("Not a signed document");
         }
         String preambleString = new String(preamble);
         byte[] xmlPreable = new byte[] { '<', '?', 'x', 'm', 'l' };
         byte[] xmlUtf8 = new byte[] { -17, -69, -65, '<', '?' };
         if (Arrays.equals(preamble, xmlPreable) || Arrays.equals(preamble, xmlUtf8)) {

            try {

               return new XMLDocumentValidator(document);
            } catch (ParserConfigurationException e) {
               throw new IOException("Not a valid XML");
            } catch (SAXException e) {
               throw new IOException("Not a valid XML");
            }
         } else if (preambleString.equals("%PDF-")) {

            return new PDFDocumentValidator(document);
         } else if (preamble[0] == 'P' && preamble[1] == 'K') {

            try {

               input.close();
            } catch (IOException e) {
            }
            input = null;
            return getInstanceForAsics(document);
         } else if (preambleString.getBytes()[0] == 0x30) {

            try {

               return new CMSDocumentValidator(document);
            } catch (CMSException e) {
               throw new IOException("Not a valid CAdES file");
            }
         } else {
            throw new RuntimeException("Document format not recognized/handled");
         }
      } finally {
         if (input != null) {
            try {
               input.close();
            } catch (IOException e) {
            }
         }
      }
   }

   /**
    * 
    * 
    * @param document
    * @return
    * @throws IOException
    */
   private static SignedDocumentValidator getInstanceForAsics(DSSDocument document) throws IOException {

      ZipInputStream asics = new ZipInputStream(document.openStream());

      try {

         String dataFileName = "";
         ByteArrayOutputStream dataFile = null;
         ByteArrayOutputStream signatures = null;
         ZipEntry entry;

         boolean cadesSigned = false;
         boolean xadesSigned = false;

         while ((entry = asics.getNextEntry()) != null) {
            if (entry.getName().matches(PATTERN_SIGNATURES_P7S)) {
               if (xadesSigned) {
                  throw new NotETSICompliantException(MSG.MORE_THAN_ONE_SIGNATURE);
               }
               signatures = new ByteArrayOutputStream();
               IOUtils.copy(asics, signatures);
               signatures.close();
               cadesSigned = true;
            } else if (entry.getName().matches(PATTERN_SIGNATURES_XML)) {
               if (cadesSigned) {
                  throw new NotETSICompliantException(MSG.MORE_THAN_ONE_SIGNATURE);
               }
               signatures = new ByteArrayOutputStream();
               IOUtils.copy(asics, signatures);
               signatures.close();
               xadesSigned = true;
            } else if (entry.getName().equalsIgnoreCase(MIMETYPE)) {
               ByteArrayOutputStream mimetype = new ByteArrayOutputStream();
               IOUtils.copy(asics, mimetype);
               mimetype.close();
               // Mime type implementers MAY use "application/vnd.etsi.asic-s+zip" to identify this format or MAY
               // maintain the original mimetype of the signed data object.
            } else if (entry.getName().indexOf("/") == -1) {
               if (dataFile == null) {

                  dataFile = new ByteArrayOutputStream();
                  IOUtils.copy(asics, dataFile);
                  dataFile.close();
                  dataFileName = entry.getName();
               } else {
                  throw new ProfileException("ASiC-S profile support only one data file");
               }
            }
         }

         if (xadesSigned) {
            ASiCXMLDocumentValidator xmlValidator = new ASiCXMLDocumentValidator(new InMemoryDocument(signatures.toByteArray()), dataFile.toByteArray(), dataFileName);
            return xmlValidator;
         } else if (cadesSigned) {
            CMSDocumentValidator pdfValidator = new CMSDocumentValidator(new InMemoryDocument(signatures.toByteArray()));
            pdfValidator.setExternalContent(new InMemoryDocument(dataFile.toByteArray()));
            return pdfValidator;
         } else {
            throw new RuntimeException("Is not xades nor cades signed");
         }

      } catch (Exception ex) {
         throw new RuntimeException(ex);
      } finally {
         try {
            asics.close();
         } catch (IOException e) {
         }
      }

   }

   private void checkTimeStampCertPath(TimestampToken t, TimestampVerificationResult result, ValidationContext ctx, AdvancedSignature signature) {

      try {

         /* Verify if there is a path up to the trusted list */
         result.getCertPathUpToTrustedList().setStatus(ResultStatus.INVALID, "cannot.reach.tsl");
         ctx.validateTimestamp(t, signature.getCertificateSource(), signature.getCRLSource(), signature.getOCSPSource());
         for (CertificateAndContext c : ctx.getNeededCertificates()) {

            if (X500PrincipalMatcher.viaAny(c.getCertificate().getSubjectX500Principal(), t.getSignerSubjectName())) {
               if (ctx.getParentFromTrustedList(c) != null) {

                  result.getCertPathUpToTrustedList().setStatus(ResultStatus.VALID, null);
                  break;
               }
            }
         }
      } catch (IOException ex) {

         result.getCertPathUpToTrustedList().setStatus(ResultStatus.UNDETERMINED, "exception.while.verifying");
      }
   }

   private boolean isEveryCertificateRefPresent(ValidationContext ctx, List<CertificateRef> refs) {

      try {

         for (CertificateAndContext neededCert : ctx.getNeededCertificates()) {

            if (neededCert.getCertificate().equals(ctx.getCertificate())) {

               LOG.fine("Don't check for the signing certificate");
               continue;
            }

            if (LOG.isLoggable(Level.INFO)) LOG.info("Looking for the CertificateRef of the " + neededCert);
            boolean found = false;
            for (CertificateRef certRef : refs) {

               if (LOG.isLoggable(Level.INFO)) LOG.info("\tCompare to " + certRef);
               MessageDigest md = MessageDigest.getInstance(certRef.getDigestAlgorithm(), "BC");
               byte[] hash = md.digest(neededCert.getCertificate().getEncoded());
               if (Arrays.equals(hash, certRef.getDigestValue())) {

                  found = true;
                  break;
               }
            }
            if (LOG.isLoggable(Level.INFO)) LOG.info("\tCerificateRef was " + (found ? "found" : "not found"));
            if (!found) {

               return false;
            }
         }
         return true;
      } catch (NoSuchProviderException e) {
         /*
          * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for
          * this exception
          */
         throw new RuntimeException(e);
      } catch (CertificateEncodingException ex) {
         throw new RuntimeException(ex);
      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException(e);
      }
   }

   /**
    * For level -XL, every certificates values contained in the ValidationContext (except the SigningCertificate) must
    * be in the CertificatesValues of the signature
    * 
    * @param ctx
    * @param certificates
    * @param signingCert
    * @return
    */
   protected boolean isEveryCertificateValuePresent(ValidationContext ctx, List<X509Certificate> certificates, X509Certificate signingCert) {

      for (CertificateAndContext neededCert : ctx.getNeededCertificates()) {

         /* We don't need the signing certificate in the XL values */
         if (neededCert.getCertificate().equals(signingCert)) {
            continue;
         }
         if (LOG.isLoggable(Level.INFO)) LOG.info("Looking for the " + neededCert + " in the signature:");
         boolean found = false;
         for (X509Certificate referencedCert : certificates) {

            if (LOG.isLoggable(Level.FINE)) LOG.fine("Compare to " + CertificateIdentifier.getId(referencedCert));
            if (referencedCert.equals(neededCert.getCertificate())) {
               found = true;
               break;
            }
         }
         if (LOG.isLoggable(Level.INFO)) LOG.info("\t --> Certificate was " + (found ? "found" : "not found!"));
         if (!found) {
            return false;
         }
      }
      return true;
   }

   /**
    * For level -XL, every X509CRL values contained in the ValidationContext must be in the RevocationValues of the
    * signature
    * 
    * @param ctx
    * @param refs
    * @param signingCert
    * @return
    */
   protected boolean everyCRLValueOrRefAreThere(ValidationContext ctx, List<?> crlValuesOrRef) {

      for (X509CRL crl : ctx.getNeededCRL()) {

         // TODO: Bob
         // if (LOG.isLoggable(Level.INFO))
         // LOG.info("Looking for CRL ref issued by " + CertificateIdentifier.getId(crl.getIssuerX500Principal()));
         boolean found = false;
         for (Object valueOrRef : crlValuesOrRef) {

            if (valueOrRef instanceof X509CRL) {

               X509CRL sigCRL = (X509CRL) valueOrRef;
               if (sigCRL.equals(crl)) {

                  found = true;
                  break;
               }
            }
            if (valueOrRef instanceof CRLRef) {

               CRLRef ref = (CRLRef) valueOrRef;
               if (ref.match(crl)) {

                  found = true;
                  break;
               }
            }
         }
         if (LOG.isLoggable(Level.INFO)) LOG.info("Ref " + (found ? " found" : " not found"));
         if (!found) {

            return false;
         }

      }
      return true;
   }

   /**
    * For level -XL or C, every BasicOCSPResponse values contained in the ValidationContext must be in the
    * RevocationValues or the RevocationRef of the signature
    * 
    * @param ctx
    * @param refs
    * @param signingCert
    * @return
    */
   protected boolean everyOCSPValueOrRefAreThere(ValidationContext ctx, List<?> ocspRespList) {

      for (BasicOCSPResp neededOCSPResp : ctx.getNeededOCSPResp()) {

         boolean found = false;
         for (Object ocspResp : ocspRespList) {

            if (ocspResp instanceof BasicOCSPResp) {

               BasicOCSPResp sigResp = (BasicOCSPResp) ocspResp;
               if (sigResp.equals(neededOCSPResp)) {

                  found = true;
                  break;
               }
            } else if (ocspResp instanceof OCSPRef) {

               OCSPRef ref = (OCSPRef) ocspResp;
               if (ref.match(neededOCSPResp)) {

                  found = true;
                  break;
               }
            }
         }
         LOG.info("OCSPResp or OCSPRef produced at '" + neededOCSPResp.getProducedAt() + "' " + (found ? "was found." : "was not found!"));
         if (!found) {

            return false;
         }
      }
      return true;
   }

   /**
    * @return the externalContent
    */
   public DSSDocument getExternalContent() {

      return externalContent;
   }

   /**
    * Retrieves the signatures found in the document
    * 
    * @return a list of AdvancedSignatures for validation purposes
    */
   public abstract List<AdvancedSignature> getSignatures();

   /**
    * Retrieves the number of signatures found in the document
    * 
    * @return number of signatures
    */
   public int numberOfSignatures() {

      List<AdvancedSignature> signatures = this.getSignatures();

      if (signatures == null) {
         return 0;
      }

      return signatures.size();
   }

   private Result resultForTimestamps(List<TimestampVerificationResult> signatureTimestampsVerification, Result levelReached) {

      if (signatureTimestampsVerification == null || signatureTimestampsVerification.isEmpty()) {
         levelReached.setStatus(ResultStatus.INVALID, "no.timestamp");
      } else {
         levelReached.setStatus(ResultStatus.VALID, null);
         for (TimestampVerificationResult result : signatureTimestampsVerification) {
            if (result.getSameDigest().isUndetermined()) {
               levelReached.setStatus(ResultStatus.UNDETERMINED, "one.of.timestamp.digest.undetermined");
            } else if (result.getSameDigest().isInvalid()) {
               levelReached.setStatus(ResultStatus.INVALID, "timestamp.dont.sign.data");
               /* Not needed to continue */
               break;
            }
         }
      }
      return levelReached;
   }

   /**
    * This method allows to set the instance of certificate verifier to be used in the validation process.
    * 
    * @param certificateVerifier the certificateVerifier to set
    */
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   /**
    * Sets the Document containing the original content to sign, for detached signature scenarios
    * 
    * @param externalContent the externalContent to set
    */
   public void setExternalContent(DSSDocument externalContent) {

      this.externalContent = externalContent;
   }

   /**
    * Validates the document and all its signatures
    * 
    * @return the validation report
    */
   public ValidationReport validateDocument() {

      Date verificationTime = new Date();

      TimeInformation timeInformation = new TimeInformation(verificationTime);

      /* Create a report for each signature */
      List<SignatureInformation> signatureInformationList = new ArrayList<SignatureInformation>();
      for (AdvancedSignature signature : getSignatures()) {

         signatureInformationList.add(validateSignature(signature, signature.getSigningTime() == null ? new Date() : signature.getSigningTime()));
      }

      return new ValidationReport(timeInformation, signatureInformationList);
   }

   /**
    * Main method for validating a signature
    * 
    * @param signature
    * @param referenceTime
    * @return the report part pertaining to the signature
    */
   protected SignatureInformation validateSignature(AdvancedSignature signature, Date referenceTime) throws DSSException {

      X509Certificate signingCert = signature.getSigningCertificate();
      if (signingCert == null) {

         LOG.severe("There is no signing certificate");
         return null;
      }
      QCStatementInformation qcStatementInformation = verifyQStatement(signingCert);
      SignatureVerification signatureVerification = new SignatureVerification(new Result(signature.checkIntegrity(this.externalContent)), signature.getSignatureAlgorithm(), signature.getId());
      try {

         ValidationContext ctx = certificateVerifier.validateCertificate(signingCert, referenceTime, signature.getCertificateSource(), signature.getCRLSource(), signature.getOCSPSource());

         TrustedListInformation info = new TrustedListInformation(ctx.getRelevantServiceInfo());

         CertPathRevocationAnalysis path = new CertPathRevocationAnalysis(ctx, info);

         /*
          * We first check the level XL, because we want to know if it's possible to check the RevocationDataRef or not
          */
         SignatureLevelXL signatureLevelXL = verifyLevelXL(signature, referenceTime, ctx, signingCert);

         /* If level XL is reached, then it's possible to rehash the values */
         SignatureLevelC signatureLevelC = verifyLevelC(signature, referenceTime, ctx, signatureLevelXL != null ? signatureLevelXL.getLevelReached().isValid() : false);

         SignatureLevelAnalysis signatureLevelAnalysis = new SignatureLevelAnalysis(signature, verifyLevelBES(signature, referenceTime, ctx), verifyLevelEPES(signature, referenceTime, ctx),
                  verifyLevelT(signature, referenceTime, ctx), signatureLevelC, verifyLevelX(signature, referenceTime, ctx), signatureLevelXL, verifyLevelA(signature, referenceTime, ctx),
                  verifyLevelLTV(signature, referenceTime, ctx));

         QualificationsVerification qualificationsVerification = verifyQualificationsElement(signature, referenceTime, ctx);

         SignatureInformation signatureInformation = new SignatureInformation(signatureVerification, path, signatureLevelAnalysis, qualificationsVerification, qcStatementInformation);

         return signatureInformation;
      } catch (IOException e) {

         throw new DSSException("Cannot read signature file", e);
      }
   }

   protected SignatureVerification[] verifyCounterSignatures(AdvancedSignature signature, ValidationContext ctx) {

      List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();

      if (counterSignatures == null) {
         return null;
      }

      List<SignatureVerification> counterSigVerifs = new ArrayList<SignatureVerification>();
      for (AdvancedSignature counterSig : counterSignatures) {
         Result counterSigResult;
         try {
            counterSigResult = new Result(counterSig.checkIntegrity(getExternalContent()));
         } catch (DSSException e) {
            // TODO Define how to handle exceptions
            throw new RuntimeException(e);
         }
         String counterSigAlg = counterSig.getSignatureAlgorithm();
         counterSigVerifs.add(new SignatureVerification(counterSigResult, counterSigAlg, signature.getId()));
      }

      SignatureVerification[] ret = new SignatureVerification[counterSigVerifs.size()];
      return counterSigVerifs.toArray(ret);
   }

   protected SignatureLevelA verifyLevelA(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      try {

         if (LOG.isLoggable(Level.INFO)) LOG.info("*** Verifying level -A");
         Result levelReached = new Result();
         List<TimestampVerificationResult> verifs = null;

         verifs = verifyTimestampsA(signature, ctx);

         // LOG.log(Level.SEVERE, "\t#Error when verifying level A", e);
         // levelReached.setStatus(ResultStatus.UNDETERMINED, "exception.while.verifying");
         SignatureLevelA signatureLevelA = new SignatureLevelA(resultForTimestamps(verifs, levelReached), verifs);
         if (LOG.isLoggable(Level.INFO)) LOG.info("*** Verifying level -A / DONE");
         return signatureLevelA;
      } catch (Exception e) {

         LOG.info("\t#Error when verifying level -A / " + e.getMessage());
         return new SignatureLevelA(new Result(ResultStatus.INVALID, "exception.while.verifying"), null);
      }
   }

   protected SignatureLevelBES verifyLevelBES(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      try {

         LOG.info("*** Verifing level -BES");
         Result signingCertRefVerification = new Result();

         if (signature.getSigningCertificate() != null) {
            signingCertRefVerification.setStatus(ResultStatus.VALID, null);
         } else {
            signingCertRefVerification.setStatus(ResultStatus.INVALID, "no.signing.certificate");
         }

         SignatureVerification[] counterSigsVerif = verifyCounterSignatures(signature, ctx);

         Result levelReached = new Result(signingCertRefVerification.isValid());

         return new SignatureLevelBES(levelReached, signature, signingCertRefVerification, counterSigsVerif, null);
      } catch (Exception ex) {
         return new SignatureLevelBES(new Result(ResultStatus.INVALID, "exception.while.verifying"), null, new Result(ResultStatus.INVALID, "exception.while.verifying"), null, null);
      }
   }

   protected SignatureLevelC verifyLevelC(AdvancedSignature signature, Date referenceTime, ValidationContext ctx, boolean rehashValues) {

      try {

         LOG.info("*** Verifing level -C");
         List<CertificateRef> refs = signature.getCertificateRefs();
         Result isEveryNeededCertInSignature = new Result();
         if (refs == null || refs.isEmpty()) {

            isEveryNeededCertInSignature.setStatus(ResultStatus.INVALID, "no.certificate.ref");
         } else {

            if (isEveryCertificateRefPresent(ctx, refs)) {

               isEveryNeededCertInSignature.setStatus(ResultStatus.VALID, null);
            } else {

               isEveryNeededCertInSignature.setStatus(ResultStatus.INVALID, "not.all.needed.certificate.ref");
            }
         }
         LOG.info("Is every needed certificate present in the signature: " + isEveryNeededCertInSignature);

         List<OCSPRef> ocspRefs = signature.getOCSPRefs();
         List<CRLRef> crlRefs = signature.getCRLRefs();

         int refCount = 0;

         Result everyNeededRevocationData = new Result(ResultStatus.VALID, null);
         refCount += ocspRefs.size();
         refCount += crlRefs.size();

         Result thereIsRevocationData = null;
         Result levelCReached = null;
         if (rehashValues) {
            if (!everyOCSPValueOrRefAreThere(ctx, ocspRefs)) {
               everyNeededRevocationData.setStatus(ResultStatus.INVALID, "not.all.needed.ocsp.ref");
            }
            if (!everyCRLValueOrRefAreThere(ctx, crlRefs)) {
               everyNeededRevocationData.setStatus(ResultStatus.INVALID, "not.all.needed.crl.ref");
            }
            levelCReached = new Result(isEveryNeededCertInSignature.getStatus() == ResultStatus.VALID && everyNeededRevocationData.getStatus() == ResultStatus.VALID);
            return new SignatureLevelC(levelCReached, isEveryNeededCertInSignature, everyNeededRevocationData);
         } else {
            thereIsRevocationData = new Result();
            if (refCount == 0) {
               thereIsRevocationData.setStatus(ResultStatus.INVALID, "no.revocation.data.reference");
            } else {
               thereIsRevocationData.setStatus(ResultStatus.VALID, "at.least.one.reference");
            }
            levelCReached = new Result(isEveryNeededCertInSignature.getStatus() == ResultStatus.VALID && thereIsRevocationData.getStatus() == ResultStatus.VALID);
            return new SignatureLevelC(levelCReached, isEveryNeededCertInSignature, thereIsRevocationData);
         }
      } catch (Exception ex) {
         return new SignatureLevelC(new Result(ResultStatus.INVALID, "exception.while.verifying"), new Result(ResultStatus.INVALID, "exception.while.verifying"), new Result(ResultStatus.INVALID,
                  "exception.while.verifying"));
      }
   }

   protected SignatureLevelEPES verifyLevelEPES(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      try {
         /*
          * We only check if a policy identifier is present. Actual signature policy validation is dependent on the
          * policy itself and therefore left to the user.
          */
         LOG.info("*** Verifing level -EPES");
         PolicyValue policyValue = signature.getPolicyId();
         Result levelReached = new Result(policyValue != null);
         return new SignatureLevelEPES(signature, levelReached);
      } catch (Exception ex) {
         return new SignatureLevelEPES(signature, new Result(ResultStatus.INVALID, "exception.while.verifying"));
      }
   }

   protected SignatureLevelLTV verifyLevelLTV(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      return null;
   }

   protected SignatureLevelT verifyLevelT(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      LOG.info("*** Verifing level -T");
      List<TimestampToken> sigTimestamps = signature.getSignatureTimestamps();
      List<TimestampVerificationResult> results = verifyTimestamps(signature, referenceTime, ctx, sigTimestamps, signature.getSignatureTimestampData());

      return new SignatureLevelT(resultForTimestamps(results, new Result()), results);
   }

   protected SignatureLevelX verifyLevelX(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      try {

         LOG.info("*** Verifing level -X");
         Result levelReached = new Result();
         levelReached.setStatus(ResultStatus.VALID, null);

         TimestampVerificationResult[] x1Results = null;
         TimestampVerificationResult[] x2Results = null;

         List<TimestampToken> timestampX1 = signature.getTimestampsX1();
         if (timestampX1 != null && !timestampX1.isEmpty()) {
            byte[] data = signature.getTimestampX1Data();
            x1Results = new TimestampVerificationResult[timestampX1.size()];
            for (int i = 0; i < timestampX1.size(); i++) {
               try {
                  TimestampToken t = timestampX1.get(i);

                  x1Results[i] = new TimestampVerificationResult(t);

                  if (!t.matchData(data)) {
                     levelReached.setStatus(ResultStatus.INVALID, "timestamp.dont.sign.data");
                     x1Results[i].setSameDigest(new Result(ResultStatus.INVALID, "timestamp.dont.sign.data"));
                  } else {
                     x1Results[i].setSameDigest(new Result(ResultStatus.VALID, null));
                  }

                  /* Verify if there is a path up to the trusted list */
                  checkTimeStampCertPath(t, x1Results[i], ctx, signature);

               } catch (NoSuchAlgorithmException ex) {
                  levelReached.setStatus(ResultStatus.UNDETERMINED, "no.such.algoritm");
               }
            }

         }

         List<TimestampToken> timestampX2 = signature.getTimestampsX2();
         if (timestampX2 != null && !timestampX2.isEmpty()) {
            byte[] data = signature.getTimestampX2Data();
            x2Results = new TimestampVerificationResult[timestampX2.size()];
            int i = 0;
            for (TimestampToken t : timestampX2) {
               try {

                  x2Results[i] = new TimestampVerificationResult(t);

                  if (!t.matchData(data)) {
                     levelReached.setStatus(ResultStatus.INVALID, "timestamp.dont.sign.data");
                     x2Results[i].setSameDigest(new Result(ResultStatus.INVALID, "timestamp.dont.sign.data"));
                  } else {
                     x2Results[i].setSameDigest(new Result(ResultStatus.VALID, null));
                  }

                  /* Verify if there is a path up to the trusted list */
                  checkTimeStampCertPath(t, x2Results[i], ctx, signature);
                  /* Verify if there is a path up to the trusted list */

               } catch (NoSuchAlgorithmException ex) {
                  levelReached.setStatus(ResultStatus.UNDETERMINED, "no.such.algoritm");
               }
            }
         }

         if ((timestampX1 == null || timestampX1.isEmpty()) && (timestampX2 == null || timestampX2.isEmpty())) {
            levelReached.setStatus(ResultStatus.INVALID, "no.timestamp");
         }

         return new SignatureLevelX(signature, levelReached, x1Results, x2Results);
      } catch (Exception ex) {
         return new SignatureLevelX(signature, new Result(ResultStatus.INVALID, "exception.while.verifying"));
      }
   }

   protected SignatureLevelXL verifyLevelXL(AdvancedSignature signature, Date referenceTime, ValidationContext ctx, X509Certificate signingCert) {

      try {

         LOG.info("*** Verifing level -XL");
         Result levelReached = new Result();

         Result isEveryNeededCertInSignature = new Result();
         isEveryNeededCertInSignature.setStatus(ResultStatus.VALID, null);

         Result isEveryNeededRevocationData = new Result();
         isEveryNeededRevocationData.setStatus(ResultStatus.VALID, null);

         List<X509Certificate> refs = signature.getCertificates();
         if (refs.isEmpty()) {

            isEveryNeededCertInSignature.setStatus(ResultStatus.INVALID, "no.certificate.value");
         } else {

            if (!isEveryCertificateValuePresent(ctx, refs, signingCert)) {

               isEveryNeededCertInSignature.setStatus(ResultStatus.INVALID, "not.all.needed.certificate.value");
            }
         }
         LOG.info("Is every needed certificate present in the signature: " + isEveryNeededCertInSignature);
         /* Count of revocation values in the -XL signature */
         List<BasicOCSPResp> ocspValues = signature.getOCSPs();
         int valueCount = ocspValues.size();
         if (!everyOCSPValueOrRefAreThere(ctx, ocspValues)) {

            isEveryNeededRevocationData.setStatus(ResultStatus.INVALID, "not.all.needed.ocsp.value");
         }
         List<X509CRL> crlValues = signature.getCRLs();
         valueCount += crlValues == null ? 0 : crlValues.size();
         if (!everyCRLValueOrRefAreThere(ctx, crlValues)) {
            isEveryNeededRevocationData.setStatus(ResultStatus.INVALID, "not.all.needed.crl.value");
         }
         /*
          * If there is no revocation value in the -XL signature, the signature is invalid
          */
         if (valueCount == 0) {
            isEveryNeededRevocationData.setStatus(ResultStatus.INVALID, "no.revocation.data.value");
         }

         levelReached.setStatus((isEveryNeededCertInSignature.getStatus() == ResultStatus.VALID && isEveryNeededRevocationData.getStatus() == ResultStatus.VALID) ? ResultStatus.VALID
                  : ResultStatus.INVALID, null);

         SignatureLevelXL xl = new SignatureLevelXL(levelReached, isEveryNeededCertInSignature, isEveryNeededRevocationData);
         LOG.info("*** Verifing level -XL / DONE");
         return xl;
      } catch (Exception ex) {

         SignatureLevelXL xl = new SignatureLevelXL(new Result(ResultStatus.INVALID, "exception.while.verifying"), new Result(ResultStatus.INVALID, "exception.while.verifying"), new Result(
                  ResultStatus.INVALID, "exception.while.verifying"));
         LOG.info("*** Verifing level -XL / DONE" + ex.getMessage());
         return xl;
      }
   }

   /**
    * 
    * @param certificate
    * @return
    */
   protected QCStatementInformation verifyQStatement(X509Certificate certificate) {

      if (certificate == null) {

         return new QCStatementInformation(null, null, null, null);
      }

      Result qCPPresent = new Result(qcp.check(new CertificateAndContext(certificate)));
      Result qCPPlusPresent = new Result(qcpplus.check(new CertificateAndContext(certificate)));
      Result qcCompliancePresent = new Result(qccompliance.check(new CertificateAndContext(certificate)));
      Result qcSCCDPresent = new Result(qcsscd.check(new CertificateAndContext(certificate)));
      return new QCStatementInformation(qCPPresent, qCPPlusPresent, qcCompliancePresent, qcSCCDPresent);
   }

   protected QualificationsVerification verifyQualificationsElement(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {

      Result qCWithSSCD = new Result();
      Result qCNoSSCD = new Result();
      Result qCSSCDStatusAsInCert = new Result();
      Result qCForLegalPerson = new Result();

      List<String> qualifiers = ctx.getQualificationStatement();
      if (qualifiers != null) {
         qCWithSSCD = new Result(qualifiers.contains(SVC_INFO + "QCWithSSCD"));
         qCNoSSCD = new Result(qualifiers.contains(SVC_INFO + "QCNoSSCD"));
         qCSSCDStatusAsInCert = new Result(qualifiers.contains(SVC_INFO + "QCSSCDStatusAsInCert"));
         qCForLegalPerson = new Result(qualifiers.contains(SVC_INFO + "QCForLegalPerson"));
      }

      return new QualificationsVerification(qCWithSSCD, qCNoSSCD, qCSSCDStatusAsInCert, qCForLegalPerson);
   }

   /**
    * Check the list of Timestamptoken. For each one a TimestampVerificationResult is produced
    * 
    * @param signature
    * @param referenceTime
    * @param ctx
    * @param tstokens
    * @param data
    * @return
    */
   protected List<TimestampVerificationResult> verifyTimestamps(AdvancedSignature signature, Date referenceTime, ValidationContext ctx, List<TimestampToken> tstokens, byte[] data) {

      List<TimestampVerificationResult> tstokenVerifs = new ArrayList<TimestampVerificationResult>();
      if (tstokens != null) {
         for (TimestampToken t : tstokens) {

            TimestampVerificationResult verif = new TimestampVerificationResult(t);
            try {

               if (t.matchData(data)) {
                  verif.setSameDigest(new Result(ResultStatus.VALID, null));
               } else {
                  verif.setSameDigest(new Result(ResultStatus.INVALID, "timestamp.dont.sign.data"));
               }

            } catch (NoSuchAlgorithmException ex) {
               /*
                * We cannot verify the digest so the verification is "undetermined"
                */
               verif.setSameDigest(new Result(ResultStatus.UNDETERMINED, "no.such.algoritm"));
            }

            /* Verify if there is a path up to the trusted list */
            checkTimeStampCertPath(t, verif, ctx, signature);

            tstokenVerifs.add(verif);
         }
      }

      return tstokenVerifs;
   }

   /**
    * Check the list of Timestamptoken. For each one a TimestampVerificationResult is produced
    * 
    * @param signature
    * @param ctx
    * @return
    */
   protected List<TimestampVerificationResult> verifyTimestampsA(AdvancedSignature signature, ValidationContext ctx) {

      List<TimestampToken> tstokens = signature.getArchiveTimestamps();
      List<TimestampVerificationResult> tstokenVerifs = new ArrayList<TimestampVerificationResult>();
      if (tstokens != null) {

         int index = 0;
         for (TimestampToken t : tstokens) {

            TimestampVerificationResult verif = new TimestampVerificationResult(t);
            try {

               byte[] data = signature.getArchiveTimestampData(index++, externalContent);
               if (t.matchData(data)) {

                  verif.setSameDigest(new Result(ResultStatus.VALID, null));
               } else {

                  verif.setSameDigest(new Result(ResultStatus.INVALID, "timestamp.dont.sign.data"));
               }
            } catch (NoSuchAlgorithmException ex) {
               /*
                * We cannot verify the digest so the verification is "undetermined"
                */
               verif.setSameDigest(new Result(ResultStatus.UNDETERMINED, "no.such.algoritm"));
            }

            /* Verify if there is a path up to the trusted list */
            checkTimeStampCertPath(t, verif, ctx, signature);

            tstokenVerifs.add(verif);
         }
      }
      return tstokenVerifs;
   }

}
