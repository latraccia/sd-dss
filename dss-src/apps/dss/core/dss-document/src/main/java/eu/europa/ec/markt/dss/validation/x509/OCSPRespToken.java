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

package eu.europa.ec.markt.dss.validation.x509;

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;

import eu.europa.ec.markt.dss.validation.certificate.OCSPRespCertificateSource;

/**
 * OCSP Signed Token
 * 
 * 
 * @version $Revision: 1927 $ - $Date: 2013-05-08 09:54:30 +0200 (mer., 08 mai 2013) $
 */

public class OCSPRespToken implements SignedToken {

	private static final Logger LOG = Logger.getLogger(OCSPRespToken.class.getName());

	private final BasicOCSPResp ocspResp;

	/**
	 * 
	 * The default constructor for OCSPRespToken.
	 * 
	 * @param ocspResp
	 */
	public OCSPRespToken(BasicOCSPResp ocspResp) {

		this.ocspResp = ocspResp;
	}

	/**
	 * @return the ocspResp
	 */
	public BasicOCSPResp getOcspResp() {

		return ocspResp;
	}

	@Override
	public X500Principal getSignerSubjectName() {

		if (ocspResp.getResponderId().toASN1Object().getName() != null) {

			return new X500Principal(ocspResp.getResponderId().toASN1Object().getName().getDEREncoded());
		} else {

			/* If we cannot find the issuer easily, then we get test every certificate */
			List<X509Certificate> certs = getWrappedCertificateSource().getCertificates();
			for (X509Certificate c : certs) {

				if (isSignedBy(c)) {

					return c.getSubjectX500Principal();
				}
			}
			LOG.warning("Don't found an signer for OCSPToken in the " + certs.size() + " certificates " + certs);
			return null;
		}
	}

	@Override
	public boolean isSignedBy(X509Certificate potentialIssuer) {

		try {

			return ocspResp.verify(potentialIssuer.getPublicKey(), "BC");
		} catch (NoSuchProviderException e) {
			/*
			 * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for this
			 * exception
			 */
			throw new RuntimeException(e);
		} catch (OCSPException e) {
			return false;
		}
	}

	@Override
	public OCSPRespCertificateSource getWrappedCertificateSource() {

		return new OCSPRespCertificateSource(ocspResp);
	}

	@Override
	public int hashCode() {

		final int prime = 31;
		int result = 1;
		result = prime * result + ((ocspResp == null) ? 0 : ocspResp.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {

		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		OCSPRespToken other = (OCSPRespToken) obj;
		if (ocspResp == null) {
			if (other.ocspResp != null) {
				return false;
			}
		} else if (!ocspResp.equals(other.ocspResp)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString(String indentStr) {

		StringBuffer res = new StringBuffer();
		res.append(indentStr).append("OCSPRespToken[");
		res.append(indentStr).append(new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(ocspResp.getProducedAt()));
		res.append(indentStr).append(", signedBy=").append(getSignerSubjectName()).append("]");
		return res.toString();
	}

	@Override
	public String toString() {

		return toString("");
	}
}
