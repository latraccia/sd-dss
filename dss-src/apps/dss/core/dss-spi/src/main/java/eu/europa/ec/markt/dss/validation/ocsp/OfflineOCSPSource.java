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

package eu.europa.ec.markt.dss.validation.ocsp;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.SingleResp;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Logger;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public abstract class OfflineOCSPSource implements OCSPSource {

   private static final Logger LOG = Logger.getLogger(OfflineOCSPSource.class.getName());

   @Override
   final public BasicOCSPResp getOCSPResponse(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {

      LOG.fine("find OCSP response");
      try {

         /**
          * TODO: (Bob 2013.05.08) Does the OCSP responses always use SHA1?<br>
          * RFC 2560:<br>
          * CertID ::= SEQUENCE {<br>
          * hashAlgorithm AlgorithmIdentifier,<br>
          * issuerNameHash OCTET STRING, -- Hash of Issuer’s DN<br>
          * issuerKeyHash OCTET STRING, -- Hash of Issuers public key<br>
          * serialNumber CertificateSerialNumber }<br>
          * 
          * ... The hash algorithm used for both these hashes, is identified in hashAlgorithm. serialNumber is the
          * serial number of the certificate for which status is being requested.
          */
         CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, issuerCertificate, certificate.getSerialNumber());
         for (BasicOCSPResp basicOCSPResp : getContainedOCSPResponses()) {

            for (SingleResp singleResp : basicOCSPResp.getResponses()) {

               if (singleResp.getCertID().equals(certId)) {

                  LOG.fine("OCSP response found");
                  return basicOCSPResp;
               }
            }
         }
         return null;
      } catch (OCSPException e) {

         LOG.severe("OCSPException: " + e.getMessage());
         return null;
      }
   }

   /**
    * Retrieves the list of BasicOCSPResp contained in the Signature.
    * 
    * @return
    */
   public abstract List<BasicOCSPResp> getContainedOCSPResponses();

}
