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

import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * Verify the status of a certificate using the Trusted List model.
 * 
 * 
 * @version $Revision: 2581 $ - $Date: 2013-09-20 10:20:52 +0200 (ven., 20 sept. 2013) $
 */

public class TrustedListCertificateVerifier implements CertificateVerifier {

   private static final Logger LOG = Logger.getLogger(TrustedListCertificateVerifier.class.getName());

   private CertificateSource trustedListCertificatesSource;

   private OCSPSource ocspSource;

   private CRLSource crlSource;

   private final ThreadLocal<ValidationContext> validationContextThreadLocal = new ThreadLocal<ValidationContext>();

   /**
    * Defines the source of CRL used by this class
    * 
    * @param crlSource the crlSource to set
    */
   public void setCrlSource(CRLSource crlSource) {
      this.crlSource = crlSource;
   }

   /**
    * Defines the source of OCSP used by this class
    * 
    * @param ocspSource the ocspSource to set
    */
   public void setOcspSource(OCSPSource ocspSource) {
      this.ocspSource = ocspSource;
   }

   /**
    * Defines how the certificate from the Trusted Lists are retrieved.
    * 
    * @param trustedListCertificatesSource the trustedListCertificatesSource to set
    */
   public void setTrustedListCertificatesSource(CertificateSource trustedListCertificatesSource) {
      this.trustedListCertificatesSource = trustedListCertificatesSource;
   }

   @Override
   public ValidationContext validateCertificate(X509Certificate cert, Date validationDate, CertificateSource optionalCertificateSource, CRLSource optionalCRLSource, OCSPSource optionalOCSPSource)
            throws IOException {

      if (cert == null) {

         throw new NullPointerException("A validation context must contains a cert");
      }
      if (validationDate == null) {

         throw new NullPointerException("A validation context must contains a validation date");
      }

      ValidationContext previous = validationContextThreadLocal.get();
      if (previous != null && previous.getCertificate().equals(cert) && previous.getValidationDate().equals(validationDate)) {
         LOG.info("We don't need to check twice for the same");
         return previous;
      }
      ValidationContext context = new ValidationContext(cert, validationDate);
      context.setCrlSource(crlSource);
      context.setOcspSource(ocspSource);
      context.setTrustedListCertificatesSource(trustedListCertificatesSource);
      context.validate(validationDate, optionalCertificateSource, optionalCRLSource, optionalOCSPSource);
      if (LOG.isLoggable(Level.INFO)) {

         LOG.info(context.getShortConclusion());
         // LOG.info(context.toString("\t"));
      }
      validationContextThreadLocal.set(context);

      return context;
   }
}
