/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Reference to a X509CRL
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class CRLRef {

   private X500Name crlIssuer;
   private Date crlIssuedTime;
   private BigInteger crlNumber;
   private String digestAlgorithm;
   private byte[] digestValue;

   /**
    * The default constructor for CRLRef.
    */
   public CRLRef() {
   }

   /**
    * 
    * The default constructor for CRLRef.
    * 
    * @param cmsRef
    * @throws ParseException
    */
   public CRLRef(CrlValidatedID cmsRef) {
      try {
         crlIssuer = cmsRef.getCrlIdentifier().getCrlIssuer();
         crlIssuedTime = cmsRef.getCrlIdentifier().getCrlIssuedTime().getDate();
         crlNumber = cmsRef.getCrlIdentifier().getCrlNumber();
         digestAlgorithm = cmsRef.getCrlHash().getHashAlgorithm().getAlgorithm().getId();
         digestValue = cmsRef.getCrlHash().getHashValue();
      } catch (ParseException ex) {
         throw new RuntimeException(ex);
      }
   }

   /**
    * 
    * @param crl
    * @return
    */
   public boolean match(X509CRL crl) {
      try {
         MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
         byte[] computedValue = digest.digest(crl.getEncoded());
         return Arrays.equals(digestValue, computedValue);
      } catch (NoSuchAlgorithmException ex) {
         throw new RuntimeException("Maybe BouncyCastle provider is not installed ?", ex);
      } catch (CRLException ex) {
         throw new RuntimeException(ex);
      }
   }

   /**
    * 
    * @return
    */
   public X500Name getCrlIssuer() {
      return crlIssuer;
   }

   /**
    * 
    * @param crlIssuer
    */
   public void setCrlIssuer(X500Name crlIssuer) {
      this.crlIssuer = crlIssuer;
   }

   /**
    * 
    * @return
    */
   public Date getCrlIssuedTime() {
      return crlIssuedTime;
   }

   /**
    * 
    * @param crlIssuedTime
    */
   public void setCrlIssuedTime(Date crlIssuedTime) {
      this.crlIssuedTime = crlIssuedTime;
   }

   /**
    * 
    * @return
    */
   public BigInteger getCrlNumber() {
      return crlNumber;
   }

   /**
    * 
    * @param crlNumber
    */
   public void setCrlNumber(BigInteger crlNumber) {
      this.crlNumber = crlNumber;
   }

   /**
    * 
    * @return
    */
   public String getDigestAlgorithm() {
      return digestAlgorithm;
   }

   /**
    * 
    * @param algorithm
    */
   public void setDigestAlgorithm(String digestAlgorithm) {
      this.digestAlgorithm = digestAlgorithm;
   }

   /**
    * 
    * @return
    */
   public byte[] getDigestValue() {
      return digestValue;
   }

   /**
    * 
    * @param digestValue
    */
   public void setDigestValue(byte[] digestValue) {
      this.digestValue = digestValue;
   }

}
