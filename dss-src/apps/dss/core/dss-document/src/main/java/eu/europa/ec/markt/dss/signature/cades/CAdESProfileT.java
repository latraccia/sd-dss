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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import eu.europa.ec.markt.dss.exception.ConfigurationException;
import eu.europa.ec.markt.dss.exception.ConfigurationException.MSG;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * This class holds the CAdES-T signature profile; it supports the inclusion of the mandatory unsigned
 * id-aa-signatureTimeStampToken attribute as specified in ETSI TS 101 733 V1.8.1, clause 6.1.1.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class CAdESProfileT extends CAdESSignatureExtension {

	private static final Logger LOG = Logger.getLogger(CAdESProfileT.class.getName());

	AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(new DefaultSignatureAlgorithmIdentifierFinder()
			.find("SHA1withRSA"));

	/**
	 * @param signatureTsa the TSA used for the signature-time-stamp attribute
	 */
	public void setSignatureTsa(TSPSource signatureTsa) {

		this.signatureTsa = signatureTsa;
	}

	@SuppressWarnings("unchecked")
	protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation si, SignatureParameters parameters) throws IOException {

		LOG.info(">>>CAdESProfileT::extendCMSSignature");
		if (this.signatureTsa == null) {

			throw new ConfigurationException(MSG.CONFIGURE_TSP_SERVER);
		}
		// if (LOG.isLoggable(Level.INFO))
		// LOG.info("Extend signature " + si.getSID());
		AttributeTable unsigned = si.getUnsignedAttributes();
		Hashtable<ASN1ObjectIdentifier, Attribute> unsignedAttrHash = null;
		if (unsigned == null) {

			unsignedAttrHash = new Hashtable<ASN1ObjectIdentifier, Attribute>();
		} else {

			unsignedAttrHash = si.getUnsignedAttributes().toHashtable();
		}
		Attribute signatureTimeStamp = getTimeStampAttribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, this.signatureTsa, digestAlgorithm,
				si.getSignature());
		unsignedAttrHash.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, signatureTimeStamp);

		SignerInformation newsi = SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(unsignedAttrHash));
		return newsi;

		// Attribute signatureTimeStamp = getTimeStampAttribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
		// this.signatureTsa, digestAlgorithm, si.getSignature());
		//
		// AttributeTable table2 = si.getUnsignedAttributes().add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
		// signatureTimeStamp);
		// /* If we add a timestamp, then we must remove every reference to timestamp -X and archive timestamp */
		// table2 = table2.remove(CAdESProfileA.id_aa_ets_archiveTimestampV2);
		// table2 = table2.remove(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp);
		//
		// SignerInformation newsi = SignerInformation.replaceUnsignedAttributes(si, table2);
		// return newsi;
		//
	}

	@Override
	@Deprecated
	public DSSDocument extendSignature(Object signatureId, DSSDocument document, SignatureParameters params) throws IOException {

		// TODO Auto-generated method stub
		return null;
	}

}
