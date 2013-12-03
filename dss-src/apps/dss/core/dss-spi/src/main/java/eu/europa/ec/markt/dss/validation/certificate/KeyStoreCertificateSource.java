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

import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

/**
 * Implements a CertificateSource using a JKS KeyStore.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class KeyStoreCertificateSource extends OfflineCertificateSource {

   private static final Logger LOG = Logger.getLogger(KeyStoreCertificateSource.class.getName());

   private File keyStoreFile;

   private String password;

   private String keyStoreType;

   /**
    * The default constructor for KeyStoreCertificateSource.
    */
   public KeyStoreCertificateSource(String keyStoreFilename, String password) {
      this(new File(keyStoreFilename), "JKS", password);
   }

   /**
    * The default constructor for KeyStoreCertificateSource.
    */
   public KeyStoreCertificateSource(File keyStoreFile, String password) {
      this(keyStoreFile, "JKS", password);
   }

   /**
    * The default constructor for MockTSLCertificateSource.
    */
   public KeyStoreCertificateSource(File keyStoreFile, String keyStoreType, String password) {
      this.keyStoreFile = keyStoreFile;
      this.keyStoreType = keyStoreType;
      this.password = password;
   }

   @Override
   public List<X509Certificate> getCertificates() {

      List<X509Certificate> certificates = new ArrayList<X509Certificate>();
      try {

         KeyStore keyStore = KeyStore.getInstance(keyStoreType);
         keyStore.load(new FileInputStream(keyStoreFile), password.toCharArray());
         Enumeration<String> aliases = keyStore.aliases();
         while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            Certificate onecert = keyStore.getCertificate(alias);
            LOG.fine("Alias " + alias + " Cert " + ((X509Certificate) onecert).getSubjectDN());
            if (onecert != null) {

               certificates.add((X509Certificate) onecert);
            }
            if (keyStore.getCertificateChain(alias) != null) {

               for (Certificate cert : keyStore.getCertificateChain(alias)) {

                  LOG.fine("Alias " + alias + " Cert " + ((X509Certificate) cert).getSubjectDN());
                  if (!certificates.contains(cert)) {

                     certificates.add((X509Certificate) cert);
                  }
               }
            }
         }
      } catch (CertificateException e) {
         throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
      } catch (KeyStoreException e) {
         throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
      } catch (NoSuchAlgorithmException e) {
         throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
      } catch (FileNotFoundException e) {
         throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
      } catch (IOException e) {
         throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
      }
      return certificates;
   }

}
