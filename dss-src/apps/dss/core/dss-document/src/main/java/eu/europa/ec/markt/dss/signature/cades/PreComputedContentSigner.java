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

package eu.europa.ec.markt.dss.signature.cades;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

/**
 * ContentSigner using a provided pre-computed signature
 * 
 * 
 * @version $Revision: 2228 $ - $Date: 2013-06-13 16:13:21 +0200 (jeu., 13 juin 2013) $
 */

public class PreComputedContentSigner implements ContentSigner {

   private byte[] preComputedSignature;
   private AlgorithmIdentifier algorithmIdentifier;
   private AlgorithmIdentifier digestAlgorithmIdentifier;

   private ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

   OutputStream nullOutputStream = new OutputStream() {

      @Override
      public void write(int arg0) throws IOException {

      }
   };

   /**
    * @param preComputedSignature the preComputedSignature to set
    */
   public PreComputedContentSigner(String algorithmIdentifier, byte[] preComputedSignature) {
      this.preComputedSignature = preComputedSignature;
      this.algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmIdentifier);
      this.digestAlgorithmIdentifier = new DefaultDigestAlgorithmIdentifierFinder().find(this.algorithmIdentifier);
   }

   /**
    * 
    * The default constructor for PreComputedContentSigner.
    * 
    * @param algorithmIdentifier
    */
   public PreComputedContentSigner(String algorithmIdentifier) {
      this(algorithmIdentifier, new byte[0]);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.bouncycastle.operator.ContentSigner#getAlgorithmIdentifier()
    */
   @Override
   public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithmIdentifier;
   }

   /**
    * @return the digestAlgorithmIdentifier
    */
   public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
      return digestAlgorithmIdentifier;
   }

   @Override
   public OutputStream getOutputStream() {
      return byteOutputStream;
      // return nullOutputStream;
   }

   @Override
   public byte[] getSignature() {
      return preComputedSignature;
   }

   /**
    * @return the preComputedSignature
    */
   public byte[] getPreComputedSignature() {
      return preComputedSignature;
   }

   /**
    * @return the byteOutputStream
    */
   public ByteArrayOutputStream getByteOutputStream() {
      return byteOutputStream;
   }

}