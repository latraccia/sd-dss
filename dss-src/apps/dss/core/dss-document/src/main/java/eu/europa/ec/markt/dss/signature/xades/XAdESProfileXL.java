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
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.ListCertificateSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertificateValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.EncapsulatedPKIDataType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.RevocationValuesType;

/**
 * XL profile of XAdES signature
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESProfileXL extends XAdESProfileX {

   private static final Logger LOG = Logger.getLogger(XAdESProfileXL.class.getName());

   /**
    * The default constructor for XAdESProfileXL.
    * 
    */
   public XAdESProfileXL() {
      super();
      LOG.info("XAdESProfileXL new instance created.");
   }

   /**
    * Adds <CertificateValues> and <RevocationValues> segments to <UnsignedSignatureProperties>.<br>
    * An XML electronic signature MAY contain at most one:<br>
    * - CertificateValues element and<br>
    * - RevocationValues element.
    * 
    * @see eu.europa.ec.markt.dss.signature.xades.XAdESProfileX#extendSignatureTag()
    */
   @Override
   protected void extendSignatureTag() throws DSSException {

      /* Go up to -X */
      super.extendSignatureTag();

      if (!xadesSignature.hasXLExtension() || SignatureFormat.XAdES_XL.equals(params.getSignatureFormat())) {

         try {

            final List<X509Certificate> certificatList = xadesSignature.getCertificates();
            final X509Certificate signingCertificate = xadesSignature.getSigningCertificate(certificatList);
            // TODO (Bob 20130423) The above two lines could be replaced by: xadesSignature.getSigningCertificate() To
            // be checked
            final Date signingTime = xadesSignature.getSigningTime();

            LOG.info("Certificate validation for XAdES-XL");
            final ValidationContext ctx = certificateVerifier.validateCertificate(signingCertificate, signingTime, new ListCertificateSource(certificatList), null, null);

            final CertificateValuesType certificateValuesT = xadesFactory.createCertificateValuesType();
            final List<Serializable> certificateValuesList = certificateValuesT.getEncapsulatedX509CertificateOrOtherCertificate();

            final List<X509Certificate> keyInfoCertList = xadesSignature.getKeyInfoCertificates();
            for (CertificateAndContext certificate : ctx.getNeededCertificates()) {

               if (keyInfoCertList.contains(certificate.getCertificate())) {

                  LOG.info("####### Already exists: " + CertificateIdentifier.getIdAsString(certificate.getCertificate()));
                  continue;
               }

               LOG.info("Add certificate value for " + certificate);
               final EncapsulatedPKIDataType encapsulatedPKIDataType = xadesFactory.createEncapsulatedPKIDataType();
               try {

                  encapsulatedPKIDataType.setValue(certificate.getCertificate().getEncoded());
               } catch (CertificateEncodingException e) {

                  throw new DSSException("certificate encoding error: " + e.getMessage(), e);
               }
               certificateValuesList.add(encapsulatedPKIDataType);
            }

            final RevocationValuesType revocationValuesT = xadesFactory.createRevocationValuesType();
            if (!ctx.getNeededCRL().isEmpty()) {

               final CRLValuesType crlValuesT = xadesFactory.createCRLValuesType();
               revocationValuesT.setCRLValues(crlValuesT);
               final List<EncapsulatedPKIDataType> encapsulatedCrlValues = crlValuesT.getEncapsulatedCRLValue();
               for (X509CRL crl : ctx.getNeededCRL()) {

                  EncapsulatedPKIDataType encapsulatedCrlValue = xadesFactory.createEncapsulatedPKIDataType();
                  encapsulatedCrlValue.setValue(crl.getEncoded());
                  encapsulatedCrlValues.add(encapsulatedCrlValue);
               }
            }
            if (!ctx.getNeededOCSPResp().isEmpty()) {

               final OCSPValuesType ocspValuesT = xadesFactory.createOCSPValuesType();
               revocationValuesT.setOCSPValues(ocspValuesT);
               final List<EncapsulatedPKIDataType> encapsulatedOcspValues = ocspValuesT.getEncapsulatedOCSPValue();
               for (BasicOCSPResp ocsp : ctx.getNeededOCSPResp()) {

                  EncapsulatedPKIDataType encapsulatedOcspValue = xadesFactory.createEncapsulatedPKIDataType();
                  encapsulatedOcspValue.setValue(OCSPUtils.fromBasicToResp(ocsp).getEncoded());
                  encapsulatedOcspValues.add(encapsulatedOcspValue);
               }
            }
            Element toRemove = xadesSignature.getCertificateValues();
            Element uspElement = xadesSignature.getUnsignedSignatureProperties();
            if (toRemove != null) {

               uspElement.removeChild(toRemove);
            }
            marshal(xadesFactory.createCertificateValues(certificateValuesT), uspElement);

            toRemove = xadesSignature.getRevocationValues();
            if (toRemove != null) {

               uspElement.removeChild(toRemove);
            }
            marshal(xadesFactory.createRevocationValues(revocationValuesT), uspElement);
         } catch (CRLException e) {

            throw new DSSException(e);
         } catch (IOException e) {

            throw new DSSException(e);
         }
      }
   }
}
