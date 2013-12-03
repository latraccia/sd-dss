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

package eu.europa.ec.markt.dss.signature.xades;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.datatype.DatatypeConfigurationException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.RespID;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.ListCertificateSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLRefType;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDListType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDType;
import eu.europa.ec.markt.tsl.jaxb.xades.CompleteCertificateRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.CompleteRevocationRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.DigestAlgAndValueType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPRefType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.ResponderIDType;

/**
 * Contains XAdES-C profile aspects
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESProfileC extends XAdESProfileT {

   private static final Logger LOG = Logger.getLogger(XAdESProfileC.class.getName());

   /*
    * Reference to the object in charge of certificates validation
    */
   protected CertificateVerifier certificateVerifier;

   /**
    * The default constructor for XAdESProfileC.
    * 
    * @throws DatatypeConfigurationException
    */
   public XAdESProfileC() {

      super();
      LOG.info("XAdESProfileC new instance created.");
   }

   /**
    * @param certificateVerifier the certificateVerifier to set
    */
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   private void incorporateCRLRefs(final CompleteRevocationRefsType completeRevocationRefs, final ValidationContext ctx) throws DSSException {

      if (!ctx.getNeededCRL().isEmpty()) {

         final CRLRefsType crlRefs = xadesFactory.createCRLRefsType();
         completeRevocationRefs.setCRLRefs(crlRefs);
         final List<CRLRefType> crlRefList = crlRefs.getCRLRef();
         for (X509CRL crl : ctx.getNeededCRL()) {

            try {

               final CRLRefType crlRef = xadesFactory.createCRLRefType();

               final CRLIdentifierType crlIdentifier = xadesFactory.createCRLIdentifierType();
               crlRef.setCRLIdentifier(crlIdentifier);
               final String issuerName = crl.getIssuerX500Principal().getName();
               crlIdentifier.setIssuer(issuerName);

               final GregorianCalendar cal = (GregorianCalendar) GregorianCalendar.getInstance();
               cal.setTime(crl.getThisUpdate());
               crlIdentifier.setIssueTime(_dataFactory.newXMLGregorianCalendar(cal));

               final DigestAlgAndValueType digestAlgAndValue = getDigestAlgAndValue(crl.getEncoded(), DigestAlgorithm.SHA1);
               crlRef.setDigestAlgAndValue(digestAlgAndValue);

               crlRefList.add(crlRef);
            } catch (CRLException ex) {

               throw new DSSException(ex);
            }
         }
      }
   }

   private void incorporateOCSPRefs(final CompleteRevocationRefsType completeRevocationRefs, final ValidationContext ctx) throws DSSException {

      if (!ctx.getNeededOCSPResp().isEmpty()) {

         final OCSPRefsType ocspRefs = xadesFactory.createOCSPRefsType();
         completeRevocationRefs.setOCSPRefs(ocspRefs);
         final List<OCSPRefType> ocspRefList = ocspRefs.getOCSPRef();
         for (BasicOCSPResp basicOcspResp : ctx.getNeededOCSPResp()) {

            try {

               final OCSPRefType ocspRef = xadesFactory.createOCSPRefType();

               final DigestAlgAndValueType digestAlgAndValue = getDigestAlgAndValue(OCSPUtils.fromBasicToResp(basicOcspResp).getEncoded(), DigestAlgorithm.SHA1);
               ocspRef.setDigestAlgAndValue(digestAlgAndValue);

               final OCSPIdentifierType ocspIdentifier = xadesFactory.createOCSPIdentifierType();
               ocspRef.setOCSPIdentifier(ocspIdentifier);

               final Date producedAt = basicOcspResp.getProducedAt();

               final GregorianCalendar cal = (GregorianCalendar) GregorianCalendar.getInstance();
               cal.setTime(producedAt);

               ocspIdentifier.setProducedAt(_dataFactory.newXMLGregorianCalendar(cal));

               final ResponderIDType responderId = xadesFactory.createResponderIDType();
               ocspIdentifier.setResponderID(responderId);
               final RespID respId = basicOcspResp.getResponderId();
               final ResponderID ocspResponderId = respId.toASN1Object();
               final DERTaggedObject derTaggedObject = (DERTaggedObject) ocspResponderId.toASN1Object();
               if (2 == derTaggedObject.getTagNo()) {

                  final ASN1OctetString keyHashOctetString = (ASN1OctetString) derTaggedObject.getObject();
                  responderId.setByKey(keyHashOctetString.getOctets());
               } else {

                  final X500Name name = X500Name.getInstance(derTaggedObject.getObject());
                  responderId.setByName(name.toString());
               }
               ocspRefList.add(ocspRef);
            } catch (IOException ex) {

               throw new DSSException(ex);
            }
         }
      }
   }

   /**
    * This format builds up taking XAdES-T signature and incorporating additional data required for validation:
    * 
    * The sequence of references to the full set of CA certificates that have been used to validate the electronic
    * signature up to (but not including ) the signer's certificate.<br>
    * A full set of references to the revocation data that have been used in the validation of the signer and CA
    * certificates.<br>
    * Adds <CompleteCertificateRefs> and <CompleteRevocationRefs> segments into <UnsignedSignatureProperties> element.
    * 
    * There SHALL be at most <b>one occurrence of CompleteRevocationRefs & CompleteCertificateRefs</b> properties in the
    * signature. Old references must be removed.
    * 
    * @see XAdESProfileT#extendSignatureTag()
    */
   @Override
   protected void extendSignatureTag() throws DSSException {

      super.extendSignatureTag();

      final SignatureFormat signatureFormat = params.getSignatureFormat();
      // for XAdES_XL the development is not conform with the standard
      if (!xadesSignature.hasCExtension() || SignatureFormat.XAdES_C.equals(signatureFormat) || SignatureFormat.XAdES_XL.equals(signatureFormat)) {

         try {

            final List<X509Certificate> certificates = xadesSignature.getCertificates();
            final X509Certificate signingCertificate = xadesSignature.getSigningCertificate(certificates);
            final Date signingTime = xadesSignature.getSigningTime();

            final ValidationContext ctx = certificateVerifier.validateCertificate(signingCertificate, signingTime, new ListCertificateSource(certificates), null, null);

            // XAdES-C: complete certificate references
            final CompleteCertificateRefsType completeCertificateRefsT = xadesFactory.createCompleteCertificateRefsType();
            final CertIDListType certIdListT = xadesFactory.createCertIDListType();
            completeCertificateRefsT.setCertRefs(certIdListT);

            final List<CertIDType> certIdList = certIdListT.getCert();
            for (CertificateAndContext certificateAndContext : ctx.getNeededCertificates()) {

               final X509Certificate certificate = certificateAndContext.getCertificate();
               if (!certificate.equals(signingCertificate)) {

                  certIdList.add(getCertID(certificate, DigestAlgorithm.SHA1));
               }
            }

            // XAdES-C: complete revocation references
            final CompleteRevocationRefsType completeRevocationRefsType = xadesFactory.createCompleteRevocationRefsType();

            incorporateCRLRefs(completeRevocationRefsType, ctx);
            incorporateOCSPRefs(completeRevocationRefsType, ctx);

            Element uspElement = xadesSignature.getUnsignedSignatureProperties();
            Element toRemove = xadesSignature.getCompleteCertificateRefs();
            if (toRemove != null) {

               uspElement.removeChild(toRemove);
            }
            marshal(xadesFactory.createCompleteCertificateRefs(completeCertificateRefsT), uspElement);

            toRemove = xadesSignature.getCompleteRevocationRefs();
            if (toRemove != null) {

               uspElement.removeChild(toRemove);
            }
            marshal(xadesFactory.createCompleteRevocationRefs(completeRevocationRefsType), uspElement);
         } catch (IOException e) {

            throw new DSSException(e);
         }
      }

   }
}
