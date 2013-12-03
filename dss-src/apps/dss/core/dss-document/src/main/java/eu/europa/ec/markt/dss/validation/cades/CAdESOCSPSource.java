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

import eu.europa.ec.markt.dss.validation.ades.SignatureOCSPSource;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.ocsp.BasicOCSPResp;

/**
 * 
 * OCSPSource that retrieves information from a CAdESSignature.
 * 
 * 
 * @version $Revision: 1959 $ - $Date: 2013-05-10 06:42:33 +0200 (ven., 10 mai 2013) $
 */

public class CAdESOCSPSource extends SignatureOCSPSource {

	private CMSSignedData cmsSignedData;
	private SignerId signerId;

	/**
	 * 
	 * The default constructor for CAdESOCSPSource.
	 * 
	 * @param encodedCMS
	 * @throws CMSException
	 */
	public CAdESOCSPSource(byte[] encodedCMS) throws CMSException {

		this(new CMSSignedData(encodedCMS));
	}

	/**
	 * 
	 * The default constructor for CAdESOCSPSource.
	 * 
	 * @param encodedCMS
	 * @throws CMSException
	 */
	public CAdESOCSPSource(CMSSignedData cms) {

		this(cms, ((SignerInformation) cms.getSignerInfos().getSigners().iterator().next()).getSID());
	}

	/**
	 * 
	 * The default constructor for CAdESOCSPSource.
	 * 
	 * @param encodedCMS
	 * @throws CMSException
	 */
	public CAdESOCSPSource(CMSSignedData cms, SignerId id) {

		this.cmsSignedData = cms;
		this.signerId = id;
	}

	@Override
	public List<BasicOCSPResp> getContainedOCSPResponses() {

		List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
		// Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
		SignerInformation si = cmsSignedData.getSignerInfos().get(signerId);
		if (si != null && si.getUnsignedAttributes() != null
				&& si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null) {

			Object object = si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues).getAttrValues().getObjectAt(0);
			RevocationValues revValues = RevocationValues.getInstance(object);
			for (BasicOCSPResponse ocspObj : revValues.getOcspVals()) {

				BasicOCSPResp bOcspObj = new BasicOCSPResp(ocspObj);
				list.add(bOcspObj);
			}
		}
		return list;
	}

}
