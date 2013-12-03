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

package eu.europa.ec.markt.dss.validation.certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.adapter.X509CertificateAdapter;

/**
 * A certificate comes from a certain context (Trusted List, CertStore, Signature) and has some properties
 * 
 * 
 * @version $Revision: 2228 $ - $Date: 2013-06-13 16:13:21 +0200 (jeu., 13 juin 2013) $
 */

@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateAndContext {
   @XmlJavaTypeAdapter(X509CertificateAdapter.class)
   private X509Certificate certificate;
   @XmlElement
   private CertificateSourceType certificateSource;
   @XmlTransient
   private Serializable context;

   private boolean signatureOk = false;
   private String signatureAlgorithm;

   public String getSignatureAlgorithm() {
      return signatureAlgorithm;
   }

   public void setSignatureAlgorithm(String algorithm) {

      signatureAlgorithm = algorithm;
   }

   public void setSignatureIsValid() {

      signatureOk = true;
   }

   public boolean isSignatureOk() {

      return signatureOk;
   }

   /**
    * 
    * The default constructor for CertificateAndContext.
    */
   public CertificateAndContext() {
   }

   /**
    * Create a CertificateAndContext wrapping the provided X509Certificate The default constructor for
    * CertificateAndContext.
    * 
    * @param cert
    */
   public CertificateAndContext(X509Certificate cert) {
      this(cert, null);
   }

   /**
    * 
    * The default constructor for CertificateAndContext.
    * 
    * @param cert
    * @param context
    */
   public CertificateAndContext(X509Certificate cert, Serializable context) {
      this.certificate = cert;
      this.context = context;
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
      CertificateAndContext other = (CertificateAndContext) obj;
      if (certificate == null) {
         if (other.certificate != null) {
            return false;
         }
      } else if (!certificate.equals(other.certificate)) {
         return false;
      }
      return true;
   }

   /**
    * Get the X509 Certificate
    * 
    * @return
    */
   public X509Certificate getCertificate() {
      return certificate;
   }

   /**
    * Get information about the source of the Certificate (TRUSTED_LIST, TRUST_STORE, ...)
    * 
    * @return
    */
   public CertificateSourceType getCertificateSource() {
      return certificateSource;
   }

   /**
    * Get information about the context from which the certificate is fetched
    * 
    * @return
    */
   public Serializable getContext() {
      return context;
   }

   @Override
   public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
      return result;
   }

   /**
    * Set the X509 Certificate
    * 
    * @param certificate
    */
   public void setCertificate(X509Certificate certificate) {
      this.certificate = certificate;
   }

   /**
    * Set information bout the source of the Certificate (TRUSTED_LIST, TRUST_STORE, ...)
    * 
    * @param certificateSource
    */
   public void setCertificateSource(CertificateSourceType certificateSource) {
      this.certificateSource = certificateSource;
   }

   /**
    * Set information about the context from which the certificate if fetched
    * 
    * @param context
    */
   public void setContext(Serializable context) {
      this.context = context;
   }

   /**
    * Indicates that a X509Certificates corresponding private key is used by an authority to sign OCSP-Responses.<br>
    * http://www.ietf.org/rfc/rfc3280.txt <br>
    * {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) keyPurpose(3)
    * ocspSigning(9)}<br>
    * OID: 1.3.6.1.5.5.7.3.9
    * 
    * @return
    */
   public boolean isOCSPSigning() {

      try {

         List<String> keyPurposes = certificate.getExtendedKeyUsage();
         if (keyPurposes != null && keyPurposes.contains(OID._1_3_6_1_5_5_7_3_9.getName())) {

            return true;
         }
      } catch (CertificateParsingException e) {

         // LOG.warning(e.getMessage());
      }
      // Responder's certificate not valid for signing OCSP responses.
      return false;
   }

   /**
    * Indicates if the revocation data should be checked for an OCSP signing certificate.<br>
    * http://www.ietf.org/rfc/rfc2560.txt?number=2560<br>
    * A CA may specify that an OCSP client can trust a responder for the lifetime of the responder's certificate. The CA
    * does so by including the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical extension. The value of the
    * extension should be NULL.
    * 
    * @return
    */
   public boolean has_id_pkix_ocsp_nocheck_extension() {

      byte[] extensionValue = certificate.getExtensionValue(OID._1_3_6_1_5_5_7_48_1_5.getName());
      try {

         if (extensionValue != null) {

            DERObject derObject = toDERObject(extensionValue);
            if (derObject instanceof DEROctetString) {

               DEROctetString derOctetString = (DEROctetString) derObject;
               byte[] data = derOctetString.getOctets();
               return data.length == 0;
            }
         }
      } catch (Exception e) {

      }
      return false;
   }

   /**
    * 
    * @param data
    * @return
    * @throws IOException
    */
   private DERObject toDERObject(byte[] data) throws IOException {

      ByteArrayInputStream inStream = new ByteArrayInputStream(data);
      ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
      DERObject object = asnInputStream.readObject();
      asnInputStream.close();
      return object;
   }

   @Override
   public String toString() {

      StringBuffer out = new StringBuffer();
      out.append("CertificateAndContext[").append(CertificateIdentifier.getId(certificate)).append("<--").append(certificate.getIssuerX500Principal()).append(", source=").append(certificateSource)
               .append(", serial=" + certificate.getSerialNumber()).append("]");
      return out.toString();
   }
}
