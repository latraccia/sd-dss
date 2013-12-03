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

package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.exception.DSSException;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Document implementation stored on file-system.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class FileDocument implements DSSDocument {

   private final File file;

   /**
    * Create a FileDocument
    * 
    * @param pathname
    */
   public FileDocument(String pathname) {
      this(new File(pathname));
   }

   /**
    * Create a FileDocument
    * 
    * @param file
    */
   public FileDocument(File file) {

      if (!file.exists()) {
         throw new RuntimeException("File Not Found: " + file.getAbsolutePath());
      }
      this.file = file;
   }

   @Override
   public FileInputStream openStream() throws IOException {

      return new FileInputStream_(file);
   }

   public boolean exists() {
      return file.exists();
   }

   public File getParentFile() {
      return file.getParentFile();
   }

   @Override
   public String getName() {
      return file.getName();
   }

   @Override
   public String getAbsolutePath() {
      return file.getAbsolutePath();
   }

   @Override
   public MimeType getMimeType() {
      return MimeType.fromFileName(getName());
   }

   @Override
   public byte[] getBytes() throws DSSException {

      try {
         return IOUtils.toByteArray(openStream());
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
}
