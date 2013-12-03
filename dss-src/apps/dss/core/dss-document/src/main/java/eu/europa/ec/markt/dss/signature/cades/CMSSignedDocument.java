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

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.cms.CMSSignedData;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A document composed by a CMSSignedData
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class CMSSignedDocument implements DSSDocument {

   protected CMSSignedData signedData;

   /**
    * 
    * The default constructor for CMSSignedDocument.
    * 
    * @param data
    * @throws IOException
    */
   public CMSSignedDocument(CMSSignedData data) throws IOException {

      this.signedData = data;
   }

   @Override
   public InputStream openStream() throws IOException {

      try {
         return new ByteArrayInputStream(getBytes());
      } catch (DSSException e) {

         throw new IOException(e);
      }
   }

   /**
    * @return the signedData
    */
   public CMSSignedData getCMSSignedData() {

      return signedData;
   }

   @Override
   public String getName() {

      return "CMSSignedDocument";
   }

   @Override
   public MimeType getMimeType() {

      return MimeType.PKCS7;
   }

   @Override
   public byte[] getBytes() throws DSSException {

      try {
         ByteArrayOutputStream output = new ByteArrayOutputStream();
         DEROutputStream derOuput = new DEROutputStream(output);
         derOuput.writeObject(ASN1Object.fromByteArray(signedData.getEncoded()));
         derOuput.close();
         return output.toByteArray();
      } catch (IOException e) {

         throw new DSSException(e);
      }
   }

   @Override
   public void save(String filePath) {

      try {

         FileOutputStream fos = new FileOutputStream(filePath);
         IOUtils.write(getBytes(), fos);
         fos.close();
      } catch (FileNotFoundException e) {
         throw new DSSException(e);
      } catch (DSSException e) {
         throw new DSSException(e);
      } catch (IOException e) {
         throw new DSSException(e);
      }
   }

   @Override
   public String getAbsolutePath() {
      return "CMSSignedDocument";
   }
}
