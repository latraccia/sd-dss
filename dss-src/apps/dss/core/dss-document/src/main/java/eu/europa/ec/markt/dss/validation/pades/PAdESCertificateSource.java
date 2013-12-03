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

package eu.europa.ec.markt.dss.validation.pades;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation.ades.SignatureCertificateSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * CertificateSource that retrieves the certificates from a PAdES Signature
 * 
 * 
 * @version $Revision: 2394 $ - $Date: 2013-08-20 07:31:55 +0200 (mar., 20 août 2013) $
 */

public class PAdESCertificateSource extends SignatureCertificateSource {

   private static final Logger LOGGER = Logger.getLogger(PAdESCertificateSource.class.getName());

   private PdfDict catalog;

   private List<X509Certificate> certs;

   /**
    * The default constructor for PAdESCertificateSource.
    * 
    * @param catalog
    */
   public PAdESCertificateSource(PdfDict catalog) {
      this.catalog = catalog;
   }

   /*
    * (non-Javadoc)
    * 
    * @see eu.europa.ec.markt.dss.validation.ades.SignatureCertificateSource#getCertificatesFromSignature()
    */
   @Override
   public List<X509Certificate> getCertificates() {

      if (certs != null) {
         return certs;
      }

      try {

         certs = new ArrayList<X509Certificate>();

         PdfDict dss = catalog.getAsDict("DSS");

         if (dss != null) {

            PdfArray certsArray = dss.getAsArray("Certs");
            if (certsArray != null) {

               CertificateFactory factory = CertificateFactory.getInstance("X509");
               LOGGER.info("There is " + certsArray.size() + " in this certsArray");
               for (int i = 0; i < certsArray.size(); i++) {

                  byte[] stream = certsArray.getBytes(i);
                  X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(stream));
                  if (!certs.contains(cert)) {

                     certs.add(cert);
                  }
               }
            }
         }
         return certs;
      } catch (IOException ex) {
         throw new RuntimeException(ex);
      } catch (CertificateException e) {
         throw new RuntimeException(e);
      }

   }
}
