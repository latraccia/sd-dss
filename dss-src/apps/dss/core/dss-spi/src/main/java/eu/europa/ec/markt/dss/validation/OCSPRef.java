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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;

/**
 * Reference an OCSPResponse
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class OCSPRef {

   private static final Logger LOG = Logger.getLogger(OCSPRef.class.getName());

   private final String digestAlgorithm;

   private final byte[] digestValue;

   private final boolean matchOnlyBasicOCSPResponse;

   /**
    * The default constructor for OCSPRef.
    */
   public OCSPRef(OcspResponsesID ocsp, boolean matchOnlyBasicOCSPResponse) {

      final OtherHash otherHash = ocsp.getOcspRepHash();
      this.digestAlgorithm = otherHash.getHashAlgorithm().getAlgorithm().getId();
      this.digestValue = ocsp.getOcspRepHash().getHashValue();
      this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
   }

   /**
    * The default constructor for OCSPRef.
    */
   public OCSPRef(String algorithm, byte[] digestValue, boolean matchOnlyBasicOCSPResponse) {

      this.digestAlgorithm = algorithm;
      this.digestValue = digestValue;
      this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
   }

   /**
    * 
    * @param ocspResp
    * @return
    */
   public boolean match(BasicOCSPResp ocspResp) {

      try {

         MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
         if (matchOnlyBasicOCSPResponse) {

            digest.update(ocspResp.getEncoded());
         } else {

            digest.update(OCSPUtils.fromBasicToResp(ocspResp).getEncoded());
         }
         byte[] computedValue = digest.digest();
         if (LOG.isLoggable(Level.INFO))
            LOG.info("Compare " + Hex.encodeHexString(digestValue) + " to computed value " + Hex.encodeHexString(computedValue) + " of BasicOCSPResp produced at " + ocspResp.getProducedAt());

         return Arrays.equals(digestValue, computedValue);
      } catch (NoSuchAlgorithmException ex) {

         throw new RuntimeException("Maybe BouncyCastle provider is not installed ?", ex);
      } catch (IOException ex) {

         throw new RuntimeException(ex);
      }
   }

   public String getDigestAlgorithm() {
      return digestAlgorithm;
   }

   public byte[] getDigestValue() {
      return digestValue;
   }
}
