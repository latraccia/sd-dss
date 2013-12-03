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

package eu.europa.ec.markt.dss.validation.crl;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

/**
 * This class if a basic skeleton that is able to retrieve the needed CRL data from a list. The child need to retrieve
 * the list of wrapped CRLs.
 * 
 * @version $Revision: 2452 $ - $Date: 2013-08-28 07:24:13 +0200 (mer., 28 août 2013) $
 */

public abstract class OfflineCRLSource implements CRLSource {

   private static final Logger LOG = Logger.getLogger(OfflineCRLSource.class.getName());

   @Override
   final public X509CRL findCrl(X509Certificate certificate, X509Certificate issuerCertificate) {

      List<X509CRL> list = getContainedCRLs();
      if (list == null) {
         return null;
      }
      X500Principal issuerX500Principal = issuerCertificate.getSubjectX500Principal();
      for (X509CRL crl : list) {

         if (crl.getIssuerX500Principal().equals(issuerX500Principal)) {

            if (LOG.isLoggable(Level.FINE)) LOG.fine("CRL found for issuer " + issuerX500Principal.toString());
            return crl;
         }
      }
      if (LOG.isLoggable(Level.FINE)) LOG.fine("CRL not found for issuer " + issuerX500Principal.toString());
      return null;
   }

   /**
    * Retrieves the list of CRLs contained in the source. If this method is implemented for a signature source than the
    * list of encapsulated CRLs in this signature is returned.<br>
    * 102 853: Null is returned if there is no CRL data in the signature.
    * 
    * @return
    */
   public abstract List<X509CRL> getContainedCRLs();

}
