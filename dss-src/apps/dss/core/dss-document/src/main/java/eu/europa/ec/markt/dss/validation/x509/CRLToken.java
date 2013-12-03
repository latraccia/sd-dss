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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;

/**
 * CRL Signed Token
 * 
 * 
 * @version $Revision: 1927 $ - $Date: 2013-05-08 09:54:30 +0200 (mer., 08 mai 2013) $
 */

public class CRLToken implements SignedToken {

	private final X509CRL x509crl;

	/**
	 * 
	 * The default constructor for CRLToken.
	 * 
	 * @param crl
	 */
	public CRLToken(X509CRL crl) {

		this.x509crl = crl;
	}

	/**
	 * @return the x509crl
	 */
	public X509CRL getX509crl() {

		return x509crl;
	}

	@Override
	public X500Principal getSignerSubjectName() {

		return x509crl.getIssuerX500Principal();
	}

	@Override
	public boolean isSignedBy(X509Certificate potentialIssuer) {

		try {
			x509crl.verify(potentialIssuer.getPublicKey());
			return true;
		} catch (InvalidKeyException e) {
			return false;
		} catch (CRLException e) {
			return false;
		} catch (NoSuchAlgorithmException e) {
			return false;
		} catch (NoSuchProviderException e) {
			/*
			 * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for
			 * this exception
			 */
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			return false;
		}
	}

	@Override
	public CertificateSource getWrappedCertificateSource() {

		return null;
	}

	@Override
	public int hashCode() {

		final int prime = 31;
		int result = 1;
		result = prime * result + ((x509crl == null) ? 0 : x509crl.hashCode());
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
		CRLToken other = (CRLToken) obj;
		if (x509crl == null) {
			if (other.x509crl != null) {
				return false;
			}
		} else if (!x509crl.equals(other.x509crl)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {

		return toString("");
	}

	@Override
	public String toString(String indentStr) {

		StringBuffer res = new StringBuffer();
		res.append(indentStr).append("CRLToken[signedBy=").append(getSignerSubjectName()).append("]");
		return res.toString();
	}

}
