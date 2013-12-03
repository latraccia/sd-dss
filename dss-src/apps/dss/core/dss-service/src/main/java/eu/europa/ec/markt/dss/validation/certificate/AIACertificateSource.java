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

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

import javax.security.auth.x500.X500Principal;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * 
 * Use the AIA attribute of a certificate to retrieve the issuer
 * 
 * @version $Revision: 2411 $ - $Date: 2013-08-26 07:01:25 +0200 (Mon, 26 Aug 2013) $
 */

public class AIACertificateSource implements CertificateSource {

   private static final Logger LOG = Logger.getLogger(AIACertificateSource.class.getName());

   private X509Certificate certificate;

   private HTTPDataLoader httpDataLoader;

   /**
    * The default constructor for AIACertificateSource.
    */
   public AIACertificateSource(X509Certificate certificate, HTTPDataLoader httpDataLoader) {

      this.certificate = certificate;
      this.httpDataLoader = httpDataLoader;
   }

   /*
    * (non-Javadoc)
    * 
    * @see
    * eu.europa.ec.markt.dss.validation.certificate.CertificateSource#getCertificateBySubjectName(javax.security.auth
    * .x500.X500Principal)
    */
   @Override
   public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {

      LOG.fine("Get issuer certificate through AIA.");
      List<CertificateAndContext> list = new ArrayList<CertificateAndContext>();
      X509Certificate cert = DSSUtils.loadIssuerCertificate(certificate, httpDataLoader);
      if (cert.getSubjectX500Principal().equals(subjectName)) {

         list.add(new CertificateAndContext());
      }
      return list;
   }
}
