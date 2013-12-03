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
import java.util.Hashtable;
import java.util.logging.Logger;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import eu.europa.ec.markt.dss.signature.SignatureParameters;

/**
 * This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
 * attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
 * defined in ETSI TS 101 733 V1.8.1, clause 6.3.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class CAdESProfileX extends CAdESProfileC {

	private static final Logger LOG = Logger.getLogger(CAdESProfileX.class.getName());

	AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(new DefaultSignatureAlgorithmIdentifierFinder()
			.find("SHA1withRSA"));

	protected int extendedValidationType = 1;

	/**
	 * Gets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
	 * id-aa-ets-certCRLTimestamp)
	 * 
	 * @return the extendedValidationType
	 */
	public int getExtendedValidationType() {

		return extendedValidationType;
	}

	/**
	 * Sets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
	 * id-aa-ets-certCRLTimestamp)
	 * 
	 * @param extendedValidationType to type to set, 1 or 2
	 */
	public void setExtendedValidationType(int extendedValidationType) {

		if (extendedValidationType != 1 && extendedValidationType != 2) {
			throw new IllegalArgumentException("The extended validation data type (CAdES-X type) shall be either 1 or 2");
		}
		this.extendedValidationType = extendedValidationType;
	}

	@Override
	protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation si, SignatureParameters parameters) throws IOException {

		si = super.extendCMSSignature(signedData, si, parameters);
		LOG.info(">>>CAdESProfileX::extendCMSSignature");

		ASN1ObjectIdentifier attributeId = null;
		ByteArrayOutputStream toTimestamp = new ByteArrayOutputStream();

		switch (getExtendedValidationType()) {
		case 1:
			attributeId = PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;

			toTimestamp.write(si.getSignature());

			// We don't include the outer SEQUENCE, only the attrType and attrValues as stated by the TS §6.3.5,
			// NOTE 2)
			toTimestamp.write(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).getAttrType().getDEREncoded());
			toTimestamp.write(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).getAttrValues().getDEREncoded());
			break;
		case 2:
			attributeId = PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
			break;
		default:
			toTimestamp.close();
			throw new IllegalStateException("CAdES-X Profile: Extended validation is set but no valid type (1 or 2)");
		}

		/* Those are common to Type 1 and Type 2 */
		toTimestamp.write(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs).getAttrType().getDEREncoded());
		toTimestamp.write(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs).getAttrValues().getDEREncoded());
		toTimestamp.write(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs).getAttrType().getDEREncoded());
		toTimestamp.write(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs).getAttrValues().getDEREncoded());

		@SuppressWarnings("unchecked")
		Hashtable<ASN1ObjectIdentifier, Attribute> unsignedAttrHash = si.getUnsignedAttributes().toHashtable();
		Attribute extendedTimeStamp = getTimeStampAttribute(attributeId, getSignatureTsa(), digestAlgorithm, toTimestamp.toByteArray());
		unsignedAttrHash.put(attributeId, extendedTimeStamp);
		toTimestamp.close();
		return SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(unsignedAttrHash));

	}

}
