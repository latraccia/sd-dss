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

package eu.europa.ec.markt.dss.validation.cades;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;

/**
 * Validation of CMS document
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class CMSDocumentValidator extends SignedDocumentValidator {

   private final CMSSignedData cmsSignedData;

   /**
    * The default constructor for PKCS7DocumentValidator.
    * 
    * @throws IOException
    * @throws CMSException
    */
   public CMSDocumentValidator(DSSDocument document) throws CMSException, IOException {

      this.document = document;
      InputStream is = null;
      try {

         is = document.openStream();
         this.cmsSignedData = new CMSSignedData(is);
      } finally {

         DSSUtils.closeQuietly(is);
      }
   }

   /**
    * The default constructor for PKCS7DocumentValidator.
    * 
    * @throws IOException
    * @throws CMSException
    */
   public CMSDocumentValidator(DSSDocument document, CMSSignedData cmsSignedData) throws CMSException, IOException {

      this.document = document;
      this.cmsSignedData = cmsSignedData;
   }

   @Override
   public List<AdvancedSignature> getSignatures() {

      List<AdvancedSignature> infos = new ArrayList<AdvancedSignature>();
      for (Object o : this.cmsSignedData.getSignerInfos().getSigners()) {

         SignerInformation signerInfo = (SignerInformation) o;
         CAdESSignature signature = new CAdESSignature(this.cmsSignedData, signerInfo.getSID());
         infos.add(signature);
      }
      return infos;
   }

}
