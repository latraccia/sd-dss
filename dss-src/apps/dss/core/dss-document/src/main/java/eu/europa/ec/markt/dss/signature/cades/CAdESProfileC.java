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

package eu.europa.ec.markt.dss.signature.cades;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CompositeCertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.ListCertificateSource;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class holds the CAdES-C signature profile; it supports the inclusion of the mandatory unsigned
 * id-aa-ets-certificateRefs and id-aa-ets-revocationRefs attributes as specified in ETSI TS 101 733 V1.8.1, clauses
 * 6.2.1 & 6.2.2.
 * 
 * 
 * @version $Revision: 2358 $ - $Date: 2013-07-09 17:05:09 +0200 (mar., 09 juil. 2013) $
 */

public class CAdESProfileC extends CAdESProfileT {

   private static final Logger LOG = Logger.getLogger(CAdESProfileC.class.getName());

   protected CertificateVerifier certificateVerifier;

   /**
    * @param certificateVerifier the certificateVerifier to set
    */
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   /**
    * Create a reference to a X509Certificate
    * 
    * @param cert
    * @return
    * @throws NoSuchAlgorithmException
    * @throws CertificateEncodingException
    */
   private OtherCertID makeOtherCertID(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {

      MessageDigest sha1digest = MessageDigest.getInstance(X509ObjectIdentifiers.id_SHA1.getId(), new BouncyCastleProvider());
      byte[] digest = sha1digest.digest(cert.getEncoded());
      if (LOG.isLoggable(Level.INFO)) LOG.info("Computing digest for " + CertificateIdentifier.getId(cert) + ": " + new DEROctetString(digest).getDERObject().toString());
      OtherHash hash = new OtherHash(digest);
      OtherCertID othercertid = new OtherCertID(new DERSequence(hash.getDERObject()));
      return othercertid;
   }

   /**
    * Create a reference to a X509CRL
    * 
    * @param crl
    * @return
    * @throws NoSuchAlgorithmException
    * @throws CRLException
    */
   private CrlValidatedID makeCrlValidatedID(X509CRL crl) throws NoSuchAlgorithmException, CRLException {

      MessageDigest sha1digest = MessageDigest.getInstance(X509ObjectIdentifiers.id_SHA1.getId(), new BouncyCastleProvider());
      OtherHash hash = new OtherHash(sha1digest.digest(crl.getEncoded()));
      BigInteger crlnumber;
      CrlIdentifier crlid;
      if (crl.getExtensionValue("2.5.29.20") != null) {
         crlnumber = new DERInteger(crl.getExtensionValue("2.5.29.20")).getPositiveValue();
         crlid = new CrlIdentifier(new X500Name(crl.getIssuerX500Principal().getName()), new DERUTCTime(crl.getThisUpdate()), crlnumber);
      } else {
         crlid = new CrlIdentifier(new X500Name(crl.getIssuerX500Principal().getName()), new DERUTCTime(crl.getThisUpdate()));
      }

      CrlValidatedID crlvid = new CrlValidatedID(hash, crlid);

      return crlvid;
   }

   /**
    * Create a reference on a OCSPResp
    * 
    * @param ocspResp
    * @return
    * @throws NoSuchAlgorithmException
    * @throws OCSPException
    * @throws IOException
    */
   private OcspResponsesID makeOcspResponsesID(BasicOCSPResp ocspResp) throws NoSuchAlgorithmException, OCSPException, IOException {

      /*
       * We hash the complete response, this is not clear in the TS but the issue was addressed here:
       * http://lists.iaik.tugraz.at/pipermail/jce-general/2007-January/005914.html
       */
      MessageDigest sha1digest = MessageDigest.getInstance(X509ObjectIdentifiers.id_SHA1.getId(), new BouncyCastleProvider());

      byte[] digestValue = sha1digest.digest(ocspResp.getEncoded());
      OtherHash hash = new OtherHash(digestValue);

      OcspResponsesID ocsprespid = new OcspResponsesID(new OcspIdentifier(ocspResp.getResponderId().toASN1Object(), new DERGeneralizedTime(ocspResp.getProducedAt())), hash);

      LOG.info("Incorporate OcspResponseId[hash=" + Hex.encodeHexString(digestValue) + ",producedAt=" + ocspResp.getProducedAt());

      return ocsprespid;
   }

   private Hashtable<ASN1ObjectIdentifier, ASN1Encodable> extendUnsignedAttributes(Hashtable<ASN1ObjectIdentifier, ASN1Encodable> unsignedAttrs, X509Certificate signingCertificate,
            SignatureParameters parameters, Date signingTime, CertificateSource optionalCertificateSource) throws IOException {

      ValidationContext validationContext = certificateVerifier.validateCertificate(signingCertificate, signingTime,
               new CompositeCertificateSource(new ListCertificateSource(parameters.getCertificateChain()), optionalCertificateSource), null, null);

      try {

         ArrayList<OtherCertID> completeCertificateRefs = new ArrayList<OtherCertID>();
         ArrayList<CrlOcspRef> completeRevocationRefs = new ArrayList<CrlOcspRef>();

         /*
          * The ETSI TS 101 733 stipulates (§6.2.1): "It references the full set of CA certificates that have been used
          * to validate an ES with Complete validation data up to (but not including) the signer's certificate. [...]
          * NOTE 1: The signer's certificate is referenced in the signing certificate attribute (see clause 5.7.3)."
          * (§6.2.1)
          * 
          * "The second and subsequent CrlOcspRef fields shall be in the same order as the OtherCertID to which they relate."
          * (§6.2.2)
          * 
          * Also, no mention of the way to order those second and subsequent fields, so we add the certificates as
          * provided by the context.
          */

         /* The SignedCertificate is in validationContext.getCertificate() */

         for (CertificateAndContext c : validationContext.getNeededCertificates()) {

            /*
             * Add every certificate except the signing certificate
             */
            if (!c.getCertificate().equals(signingCertificate)) {

               completeCertificateRefs.add(makeOtherCertID(c.getCertificate()));
            }

            ArrayList<CrlValidatedID> crlListIdValues = new ArrayList<CrlValidatedID>();
            ArrayList<OcspResponsesID> ocspListIDValues = new ArrayList<OcspResponsesID>();

            /*
             * Record each CRL and OCSP with a reference to the corresponding certificate
             */
            for (CRL relatedcrl : validationContext.getRelatedCRLs(c)) {
               crlListIdValues.add(makeCrlValidatedID((X509CRL) relatedcrl));
            }

            for (BasicOCSPResp relatedocspresp : validationContext.getRelatedOCSPResp(c)) {
               ocspListIDValues.add(makeOcspResponsesID(relatedocspresp));
            }

            CrlValidatedID[] crlListIdArray = new CrlValidatedID[crlListIdValues.size()];
            OcspResponsesID[] ocspListIDArray = new OcspResponsesID[ocspListIDValues.size()];

            completeRevocationRefs.add(new CrlOcspRef(new CrlListID(crlListIdValues.toArray(crlListIdArray)), new OcspListID(ocspListIDValues.toArray(ocspListIDArray)), null));
         }

         OtherCertID[] otherCertIDArray = new OtherCertID[completeCertificateRefs.size()];
         CrlOcspRef[] crlOcspRefArray = new CrlOcspRef[completeRevocationRefs.size()];

         unsignedAttrs.put(PKCSObjectIdentifiers.id_aa_ets_certificateRefs,
                  new Attribute(PKCSObjectIdentifiers.id_aa_ets_certificateRefs, new DERSet(new DERSequence(completeCertificateRefs.toArray(otherCertIDArray)))));
         unsignedAttrs.put(PKCSObjectIdentifiers.id_aa_ets_revocationRefs,
                  new Attribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs, new DERSet(new DERSequence(completeRevocationRefs.toArray(crlOcspRefArray)))));

      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException(e);
      } catch (CertificateEncodingException e) {
         throw new RuntimeException(e);
      } catch (OCSPException e) {
         throw new RuntimeException(e);
      } catch (IOException e) {
         throw new RuntimeException(e);
      } catch (CRLException e) {
         throw new RuntimeException(e);
      }

      return unsignedAttrs;
   }

   @SuppressWarnings("unchecked")
   @Override
   protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation si, SignatureParameters parameters) throws IOException {

      /* Get parent unsigned attributes */
      SignerInformation newSi = super.extendCMSSignature(signedData, si, parameters);
      LOG.info(">>>CAdESProfileC::extendCMSSignature");
      Hashtable<ASN1ObjectIdentifier, ASN1Encodable> unsignedAttrs = newSi.getUnsignedAttributes().toHashtable();

      /* Extends unsigned attributes */
      CAdESSignature signature = new CAdESSignature(signedData, si.getSID());
      unsignedAttrs = extendUnsignedAttributes(unsignedAttrs, signature.getSigningCertificate(), parameters, signature.getSigningTime(), signature.getCertificateSource());

      /* Return new SignerInformation */
      return SignerInformation.replaceUnsignedAttributes(newSi, new AttributeTable(unsignedAttrs));
   }

}
