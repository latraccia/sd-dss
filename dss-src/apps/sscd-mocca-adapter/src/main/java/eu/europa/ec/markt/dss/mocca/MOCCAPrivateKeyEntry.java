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

package eu.europa.ec.markt.dss.mocca;

import eu.europa.ec.markt.dss.DSSException;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

import at.gv.egiz.smcc.SignatureCard.KeyboxName;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 
 * A DSSPrivateKeyEntry implementation for the MOCCA framework
 * 
 */
public class MOCCAPrivateKeyEntry implements DSSPrivateKeyEntry {

   private X509Certificate signingCert;

   private KeyboxName keyboxName;

   private int index;

   private byte[] atr;

   private EncryptionAlgorithm encryptionAlgorithm;

   private Certificate[] certificateChain = new Certificate[1];

   /**
    * This constructor is used when working with several cards
    * 
    * @param signingCert the certificate
    * @param keyboxName identifies signature usage/algorithm
    * @param index the position of this KeyEntry in the overall list
    * @param atr the ATR associated with this key
    * @throws Exception
    */
   public MOCCAPrivateKeyEntry(final byte[] signingCert, final KeyboxName keyboxName, final int index, final byte[] atr) throws Exception {

      initialise(signingCert, keyboxName, atr);
      this.index = index;
   }

   /**
    * @param signingCert
    * @param keyboxName
    * @param atr
    * @throws CertificateException
    * @throws DSSException
    */
   private void initialise(final byte[] signingCertBinary, final KeyboxName keyboxName, final byte[] atr) throws Exception {

      CertificateFactory factory = CertificateFactory.getInstance("X509", new BouncyCastleProvider());
      this.signingCert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(signingCertBinary));
      if (signingCert == null) {

         throw new DSSException("Signing certificate is missing");
      }
      this.keyboxName = keyboxName;
      if (keyboxName == null) {

         throw new DSSException("KeyboxNema is missing");
      }
      this.atr = atr;
      String encryptionAlgo = signingCert.getPublicKey().getAlgorithm(); // Can be: DH, DSA, RSA & EC
      this.encryptionAlgorithm = EncryptionAlgorithm.forName(encryptionAlgo);
      this.certificateChain[0] = this.signingCert;
   }

   @Override
   public X509Certificate getCertificate() {
      return signingCert;
   }

   @Override
   public Certificate[] getCertificateChain() {
      return certificateChain;
   }

   @Override
   public EncryptionAlgorithm getEncryptionAlgorithm() throws NoSuchAlgorithmException {
      return encryptionAlgorithm;
   }

   /**
    * Gets the signature algorithm used to sign the enclosed certificate.
    * 
    * @return the name (something like SHA1WithRSA)
    */
   public String getX509SignatureAlgorithmName() {
      return signingCert.getSigAlgName();
   }

   /**
    * @return the keyboxName
    */
   public KeyboxName getKeyboxName() {
      return keyboxName;
   }

   /**
    * Gets the position of this key in the list of all keys
    * 
    * @return
    */
   public int getPos() {
      return index;
   }

   /**
    * Get the ATR associated with this key
    * 
    * @return the ATR
    */
   public byte[] getAtr() {
      return atr;
   }
}
