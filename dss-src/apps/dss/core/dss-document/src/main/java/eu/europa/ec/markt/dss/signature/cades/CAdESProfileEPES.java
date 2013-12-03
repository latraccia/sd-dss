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

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureParameters.Policy;

/**
 * This class holds the CAdES-EPES signature profile; it supports the inclusion of the mandatory signed id_aa_ets_sigPolicyId
 * attribute as specified in ETSI TS 101 733 V1.8.1, clause 5.8.1.
 * 
 * 
 * @version $Revision: 2014 $ - $Date: 2013-05-16 07:51:05 +0200 (jeu., 16 mai 2013) $
 */

public class CAdESProfileEPES extends CAdESProfileBES {

	/**
	 * The default constructor for CAdESProfileEPES.
	 */
	public CAdESProfileEPES() {

	}

	/**
	 * The default constructor for CAdESProfileEPES.
	 */
	public CAdESProfileEPES(boolean padesUsage) {

		super(padesUsage);
	}

	@Override
	public Hashtable<ASN1ObjectIdentifier, ASN1Encodable> getSignedAttributes(SignatureParameters parameters) {

		Hashtable<ASN1ObjectIdentifier, ASN1Encodable> signedAttrs = super.getSignedAttributes(parameters);

		Policy policy = parameters.getSignaturePolicy();
		if (policy != null && policy.getId() != null) {

			SignaturePolicyIdentifier sigPolicy = null;
			if (policy.getId() != "") { // explicit

				DERObjectIdentifier derOId = new DERObjectIdentifier(policy.getId());
				AlgorithmIdentifier ai = new AlgorithmIdentifier(policy.getDigestAlgo().getOid());
				OtherHashAlgAndValue ohaav = new OtherHashAlgAndValue(ai, new DEROctetString(policy.getHashValue()));
				sigPolicy = new SignaturePolicyIdentifier(new SignaturePolicyId(derOId, ohaav));
			} else {// implicit

				sigPolicy = new SignaturePolicyIdentifier();
				sigPolicy.isSignaturePolicyImplied();
			}
			Attribute aPolicy = new Attribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, new DERSet(sigPolicy));
			signedAttrs.put(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, aPolicy);
		}
		return signedAttrs;

	}

}
