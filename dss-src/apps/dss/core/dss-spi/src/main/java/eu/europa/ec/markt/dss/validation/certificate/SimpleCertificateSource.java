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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Creates an empty CertificateSource. Any certificate can be added using {@link #}
 * 
 * 
 * @version $Revision: 1457 $ - $Date: 2012-11-30 14:24:19 +0100 (Fri, 30 Nov 2012) $
 */

public class SimpleCertificateSource extends OfflineCertificateSource {

   private List<X509Certificate> certificates = new ArrayList<X509Certificate>();

   /**
    * The default constructor for SimpleCertificateSource.
    */
   public SimpleCertificateSource() {

   }

   /**
    * This method allows to add a certificate.
    * 
    * @param cert
    */
   public void add(X509Certificate cert) {

      certificates.add(cert);
   }

   @Override
   public List<X509Certificate> getCertificates() {

      return certificates;
   }
}
