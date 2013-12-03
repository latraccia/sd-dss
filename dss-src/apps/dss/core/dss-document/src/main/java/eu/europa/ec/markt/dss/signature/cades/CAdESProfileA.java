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

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import java.io.IOException;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

/**
 * This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
 * id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
 * 
 * "If the certificate-values and revocation-values attributes are not present in the CAdES-BES or CAdES-EPES, then they
 * shall be added to the electronic signature prior to computing the archive time-stamp token." is the reason we extend
 * from the XL profile.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class CAdESProfileA extends CAdESProfileXL {

   private static final Logger LOG = Logger.getLogger(CAdESProfileA.class.getName());

   public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");

   @Override
   @SuppressWarnings("unchecked")
   protected SignerInformation extendCMSSignature(CMSSignedData cmsSignedData, SignerInformation si, SignatureParameters parameters) throws IOException {

      si = super.extendCMSSignature(cmsSignedData, si, parameters);
      LOG.info("CAdESProfileA::extendCMSSignature");
      final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, si);

      final List<TimestampToken> archiveTimestamps = cadesSignature.getArchiveTimestamps();
      final int index = archiveTimestamps == null ? 0 : archiveTimestamps.size();

      final Hashtable<ASN1ObjectIdentifier, Attribute> unsignedAttrHash = si.getUnsignedAttributes().toHashtable();

      final DSSDocument originalDocument = parameters.getOriginalDocument();
      byte[] data = cadesSignature.getArchiveTimestampData(index, originalDocument);
      final Attribute archiveTimeStamp = getTimeStampAttribute(CAdESProfileA.id_aa_ets_archiveTimestampV2, getSignatureTsa(), digestAlgorithm, data);

      Attribute a = unsignedAttrHash.put(CAdESProfileA.id_aa_ets_archiveTimestampV2, archiveTimeStamp);
      if (a != null) {

         System.out.println("attribute was replaced.");
      }

      final SignerInformation newsi = SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(unsignedAttrHash));
      return newsi;
   }

}
