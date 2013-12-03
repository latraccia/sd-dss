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

package eu.europa.ec.markt.dss.validation.x509;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.validation.CertificateStatus;
import eu.europa.ec.markt.dss.validation.X500PrincipalMatcher;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceFactory;

import javax.security.auth.x500.X500Principal;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * SignedToken containing a X509Certificate
 * 
 * 
 * @version $Revision: 2411 $ - $Date: 2013-08-26 07:01:25 +0200 (lun., 26 août 2013) $
 */

public class CertificateToken implements SignedToken {

   private final CertificateSourceFactory sourceFactory;

   private final CertificateAndContext certAndContext;

   private CertificateStatus status;

   /**
    * Create a CertificateToken
    * 
    * @param cert
    */
   public CertificateToken(CertificateAndContext cert) {

      this(cert, null);
   }

   /**
    * Create a CertificateToken
    * 
    * @param cert
    * @param sourceFactory
    */
   public CertificateToken(CertificateAndContext cert, CertificateSourceFactory sourceFactory) {

      this.certAndContext = cert;
      this.sourceFactory = sourceFactory;
   }

   @Override
   public X500Principal getSignerSubjectName() {

      return certAndContext.getCertificate().getIssuerX500Principal();
   }

   /**
    * @return the cert
    */
   public CertificateAndContext getCertificateAndContext() {

      return certAndContext;
   }

   /**
    * @return the cert
    */
   public X509Certificate getCertificate() {

      return certAndContext.getCertificate();
   }

   @Override
   public boolean isSignedBy(X509Certificate potentialIssuer) {

      try {

         getCertificate().verify(potentialIssuer.getPublicKey());
         certAndContext.setSignatureAlgorithm(getCertificate().getSigAlgName());
         certAndContext.setSignatureIsValid();
         return true;
      } catch (InvalidKeyException e) { // on incorrect key.
      } catch (CertificateException e) { // on encoding errors.
      } catch (NoSuchAlgorithmException e) { // on unsupported signature algorithms.
      } catch (SignatureException e) { // on signature errors
      } catch (NoSuchProviderException e) { // if there's no default provider.
         /*
          * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for
          * this exception
          */
         throw new RuntimeException(e);
      }
      return false;
   }

   /**
    * @param status the status to set
    */
   public void setStatus(CertificateStatus status) {

      this.status = status;
   }

   /**
    * @return the status
    */
   public CertificateStatus getStatus() {

      return status;
   }

   /**
    * An X509Certificate may contain information about his issuer in the AIA attribute.
    */
   @Override
   public CertificateSource getWrappedCertificateSource() {

      if (sourceFactory != null) {
         CertificateSource source = sourceFactory.createAIACertificateSource(getCertificate());
         return source;
      } else {
         return null;
      }
   }

   @Override
   public int hashCode() {

      final int prime = 31;
      int result = 1;
      try {
         result = prime * result + ((certAndContext == null) ? 0 : Arrays.hashCode(getCertificate().getEncoded()));
      } catch (CertificateException ex) {
         return prime;
      }
      return result;
   }

   @Override
   public boolean equals(Object obj) {

      if (this == obj) {
         return true;
      }
      if (obj == null) {
         return false;
      }
      if (getClass() != obj.getClass()) {
         return false;
      }
      CertificateToken other = (CertificateToken) obj;
      if (certAndContext == null) {
         if (other.certAndContext != null) {
            return false;
         }
      } else if (!certAndContext.equals(other.certAndContext)) {
         return false;
      }
      return true;
   }

   @Override
   public String toString(String indentStr) {

      StringBuffer res = new StringBuffer();
      X509Certificate certificate = getCertificate();
      boolean selfSigned = X500PrincipalMatcher.viaAny(certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal());
      res.append(indentStr).append("CertificateToken[").append(CertificateIdentifier.getId(certificate)).append("<--");
      if (selfSigned) {

         res.append("SELF-SIGNED]");
      } else {

         res.append(certificate.getIssuerX500Principal()).append("]");
      }
      return res.toString();
   }

   @Override
   public String toString() {

      return toString("");
   }
}
