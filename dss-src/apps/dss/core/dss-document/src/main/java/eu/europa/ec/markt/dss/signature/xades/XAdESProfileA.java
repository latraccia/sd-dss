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

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.XAdESTimeStampType;

import org.w3c.dom.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Logger;

/**
 * Holds level A aspects of XAdES
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESProfileA extends XAdESProfileXL {

   private static final Logger LOG = Logger.getLogger(XAdESProfileA.class.getName());

   /**
    * The default constructor for XAdESProfileA.
    * 
    */
   public XAdESProfileA() {

      super();
      LOG.info("XAdESProfileA new instance created.");
   }

   /**
    * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the TSA
    * (messageImprint) is computed on the XAdES-X-L form of the electronic signature and the signed data objects.<br>
    * 
    * A XAdES-A form MAY contain several ArchiveTimeStamp elements.
    * 
    * @see eu.europa.ec.markt.dss.signature.xades.XAdESProfileXL#extendSignatureTag()
    */
   @Override
   protected void extendSignatureTag() throws DSSException {

      /* Up to -XL */
      super.extendSignatureTag();

      try {

         final DSSDocument detachedDocument = params.getOriginalDocument();
         xadesSignature.checkIntegrity(detachedDocument);

         final List<TimestampToken> archiveTimestamps = xadesSignature.getArchiveTimestamps();
         final int index = archiveTimestamps.size();

         final MessageDigest digest = MessageDigest.getInstance(timestampDigestAlgorithm.getName());
         final byte[] data = xadesSignature.getArchiveTimestampData(index, null);
         digest.update(data);
         final byte[] digestValue = digest.digest();
         final XAdESTimeStampType xadesTimeStampType = createXAdESTimeStampType(timestampDigestAlgorithm, XAdESSignature.XMLDSIG_DEFAULT_CANONICALIZATION_METHOD, digestValue);
         final Element uspElement = xadesSignature.getUnsignedSignatureProperties();
         marshal(xades141Factory.createArchiveTimeStamp(xadesTimeStampType), uspElement);
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException(e);
      }
   }
}
