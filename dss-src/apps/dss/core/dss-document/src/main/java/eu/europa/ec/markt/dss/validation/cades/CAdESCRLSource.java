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

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.ades.SignatureCRLSource;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.util.StoreException;

/**
 * 
 * CRLSource that retrieves information from a CAdES signature.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class CAdESCRLSource extends SignatureCRLSource {

	private CMSSignedData cmsSignedData;

	private SignerId signerId;

	/**
	 * 
	 * The default constructor for CAdESCRLSource.
	 * 
	 * @param encodedCMS
	 * @throws CMSException
	 */
	public CAdESCRLSource(byte[] encodedCMS) throws CMSException {

		this(new CMSSignedData(encodedCMS));
	}

	/**
	 * 
	 * The default constructor for CAdESCRLSource.
	 * 
	 * @param encodedCMS
	 * @throws CMSException
	 */
	public CAdESCRLSource(CMSSignedData cms) {

		this(cms, ((SignerInformation) cms.getSignerInfos().getSigners().iterator().next()).getSID());
	}

	/**
	 * 
	 * The default constructor for CAdESCRLSource.
	 * 
	 * @param encodedCMS
	 * @throws CMSException
	 */
	public CAdESCRLSource(CMSSignedData cms, SignerId id) {

		this.cmsSignedData = cms;
		this.signerId = id;
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<X509CRL> getContainedCRLs() {

		List<X509CRL> list = new ArrayList<X509CRL>();
		try {

			// Adds CRLs contained in SignedData
			for (CertificateList cl : (Collection<CertificateList>) cmsSignedData.getCRLs().getMatches(null)) {

				X509CRLObject crl = new X509CRLObject(cl);
				list.add(crl);
			}
			// Adds CRLs in -XL ... inside SignerInfo attribute if present
			SignerInformation si = cmsSignedData.getSignerInfos().get(signerId);
			if (si != null && si.getUnsignedAttributes() != null
					&& si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null) {

				RevocationValues revValues = RevocationValues.getInstance(si.getUnsignedAttributes()
						.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues).getAttrValues().getObjectAt(0));

				for (CertificateList crlObj : revValues.getCrlVals()) {

					X509CRLObject crl = new X509CRLObject(crlObj);
					list.add(crl);
				}
			}
		} catch (StoreException e) {

			throw new DSSException(e);
		} catch (CRLException e) {

			throw new DSSException(e);
		}
		return list.size() > 0 ? list : null;
	}

}
