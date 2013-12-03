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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;

/**
 * RevocationData for a specific SignedToken
 * 
 * 
 * @version $Revision: 2171 $ - $Date: 2013-05-31 22:38:16 +0200 (ven., 31 mai 2013) $
 */

public class RevocationData {

   private SignedToken targetToken;

   private Object revocationData;

   /**
    * The default constructor for RevocationData.
    */
   public RevocationData() {

   }

   /**
    * 
    * The default constructor for RevocationData.
    * 
    * @param signedToken
    */
   public RevocationData(SignedToken signedToken) {

      this.targetToken = signedToken;
   }

   /**
    * The target of this revocation data
    * 
    * @return
    */
   public SignedToken getTargetToken() {

      return targetToken;
   }

   /**
    * The value of the revocation data
    * 
    * @return
    */
   public Object getRevocationData() {

      return revocationData;
   }

   /**
    * Set the value of the revocation data
    * 
    * @param revocationData
    */
   public void setRevocationData(Object revocationData) {

      if (targetToken instanceof CertificateToken) {

         if (!(revocationData instanceof CertificateSourceType) && !(revocationData instanceof BasicOCSPResp) && !(revocationData instanceof X509CRL)) {

            throw new IllegalArgumentException("For " + targetToken + " only OCSP, CRL or CertificateSourceType are valid. (Trying to add "
                     + revocationData.getClass().getSimpleName() + ").");
         }
      }
      this.revocationData = revocationData;
   }

   public String toString(String indentStr) {

      StringBuffer res = new StringBuffer();
      res.append(indentStr).append("RevocationData[\n");
      indentStr += "\t";
      res.append(indentStr).append(targetToken != null ? targetToken.toString() : "Token=null").append("\n");
      res.append(indentStr).append("data[");
      if (revocationData instanceof X509CRL) {

         res.append("CRL[from=" + ((X509CRL) revocationData).getIssuerX500Principal() + "]");
      } else if (revocationData instanceof BasicOCSPResp) {

         res.append("OCSP[from=" + (BasicOCSPResp) revocationData + "]");
      } else if (revocationData instanceof X509Certificate) {

         res.append("Certificate[" + CertificateIdentifier.getId((X509Certificate) revocationData) + "]");
      } else {

         if (revocationData != null) {

            res.append(revocationData.toString());
         } else {

            res.append("*** NO VALIDATION DATA AVAILABLE ***");
         }
      }
      res.append("]\n");
      indentStr = indentStr.substring(1);
      res.append(indentStr).append("]");
      return res.toString();
   }

   @Override
   public String toString() {

      try {

         return toString("");
      } catch (Exception e) {

         return super.toString();
      }
   }
}
