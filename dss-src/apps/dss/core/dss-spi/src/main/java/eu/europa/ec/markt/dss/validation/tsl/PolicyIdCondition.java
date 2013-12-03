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

package eu.europa.ec.markt.dss.validation.tsl;

import java.io.IOException;
import java.io.Serializable;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extension;

import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;

/**
 * Check if a certificate has a specific policy id
 * 
 * 
 * @version $Revision: 2020 $ - $Date: 2013-05-16 07:54:22 +0200 (jeu., 16 mai 2013) $
 */

public class PolicyIdCondition implements Condition, Serializable {

	private static final long serialVersionUID = 7590885101177874819L;

	private String policyOid;

	/**
	 * The default constructor for PolicyIdCondition.
	 */
	public PolicyIdCondition() {
	}

	/**
	 * 
	 * The default constructor for PolicyIdCondition.
	 * 
	 * @param policyId
	 */
	public PolicyIdCondition(String policyId) {
		this.policyOid = policyId;
	}

	/**
	 * @return the policyOid
	 */
	public String getPolicyOid() {
		return policyOid;
	}

	@Override
	public boolean check(CertificateAndContext cert) {

		// Bob (20130516) deprecated: byte[] certificatePolicies =
		// cert.getCertificate().getExtensionValue(X509Extensions.CertificatePolicies.getId());
		byte[] certificatePolicies = cert.getCertificate().getExtensionValue(X509Extension.certificatePolicies.getId());
		if (certificatePolicies != null) {

			try {

				ASN1InputStream input = new ASN1InputStream(certificatePolicies);
				DEROctetString s = (DEROctetString) input.readObject();
				input.close();
				byte[] content = s.getOctets();
				input = new ASN1InputStream(content);
				DERSequence seq = (DERSequence) input.readObject();
				input.close();
				for (int i = 0; i < seq.size(); i++) {

					PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(i));
					if (policyInfo.getPolicyIdentifier().getId().equals(policyOid)) {

						return true;
					}
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return false;
	}
}
