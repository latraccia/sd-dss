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

package eu.europa.ec.markt.dss.signature.xades;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.tsl.jaxb.xades.XAdESTimeStampType;

/**
 * This class represents the implementation of XAdES level -X extension.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESProfileX extends XAdESProfileC {

   private static final Logger LOG = Logger.getLogger(XAdESProfileX.class.getName());

   /**
    * The default constructor for XAdESProfileX.
    * 
    */
   public XAdESProfileX() {

      super();
      LOG.info("XAdESProfileX new instance created.");
   }

   /**
    * Adds <SigAndRefsTimeStamp> segment to <UnsignedSignatureProperties><br>
    * The time-stamp is placed on the the digital signature (ds:Signature element), the time-stamp(s) present in the
    * XAdES-T form, the certification path references and the revocation status references.
    * 
    * A XAdES-X form MAY contain several SigAndRefsTimeStamp elements, obtained from different TSAs.
    * 
    * @see XAdESProfileC#extendSignatureTag()
    */
   @Override
   protected void extendSignatureTag() throws DSSException {

      /* Go up to -C */
      super.extendSignatureTag();

      final SignatureFormat signatureFormat = params.getSignatureFormat();
      // for XAdES_XL the development is not conform with the standard
      if (!xadesSignature.hasXExtension() || SignatureFormat.XAdES_X.equals(signatureFormat) || SignatureFormat.XAdES_XL.equals(signatureFormat)) {

         try {

            MessageDigest digest = MessageDigest.getInstance(timestampDigestAlgorithm.getName());
            digest.update(xadesSignature.getTimestampX1Data());
            XAdESTimeStampType timeStampXadesX1 = createXAdESTimeStampType(timestampDigestAlgorithm, timestampCanonicalizationMethod, digest.digest());
            Element uspElement = xadesSignature.getUnsignedSignatureProperties();
            if (SignatureFormat.XAdES_XL.equals(params.getSignatureFormat())) {

               NodeList toRemoveList = xadesSignature.getSigAndRefsTimeStamp();
               for (int index = 0; index < toRemoveList.getLength(); index++) {

                  uspElement.removeChild(toRemoveList.item(index));
               }
            }
            marshal(xadesFactory.createSigAndRefsTimeStamp(timeStampXadesX1), uspElement);
         } catch (NoSuchAlgorithmException e) {

            throw new DSSException(e);
         }
      }
   }
}
