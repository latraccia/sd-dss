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

package eu.europa.ec.markt.dss.ws;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Container for any kind of document that is to be transferred to and from web service endpoints.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class WSDocument implements DSSDocument {

   private byte[] binary;

   /**
    * The default constructor for WSDocument.
    */
   public WSDocument() {

   }

   /**
    * 
    * The default constructor for WSDocument.
    * 
    * @param doc
    * @throws IOException
    */
   public WSDocument(DSSDocument doc) throws IOException {

      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      IOUtils.copy(doc.openStream(), buffer);
      binary = buffer.toByteArray();
   }

   /**
    * @return the binary
    */
   public byte[] getBinary() {

      return binary;
   }

   /**
    * @param binary the binary to set
    */
   public void setBinary(byte[] binary) {

      this.binary = binary;
   }

   @Override
   public InputStream openStream() throws IOException {

      return new ByteArrayInputStream(binary);
   }

   @Override
   public String getName() {

      return "WSDocument";
   }

   @Override
   public MimeType getMimeType() {

      return null;
   }

   @Override
   public byte[] getBytes() throws DSSException {

      return binary;
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
      return "WSDocument";
   }
}