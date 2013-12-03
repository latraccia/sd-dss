/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.signature.token;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * Wrapper of a PrivateKeyEntry coming from a KeyStore.
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */
public class KSPrivateKeyEntry implements DSSPrivateKeyEntry {

	private X509Certificate certificate;

	private Certificate[] certificateChain;

	private PrivateKey privateKey;

	/**
	 * The default constructor for DSSPrivateKeyEntry.
	 */
	public KSPrivateKeyEntry(PrivateKeyEntry privateKeyEntry) {
		certificate = (X509Certificate) privateKeyEntry.getCertificate();
		certificateChain = privateKeyEntry.getCertificateChain();
		privateKey = privateKeyEntry.getPrivateKey();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.signature.token.DSSPrivateKey#getCertificate()
	 */
	@Override
	public X509Certificate getCertificate() {
		return certificate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.signature.token.DSSPrivateKey#getCertificateChain()
	 */
	@Override
	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	/**
	 * 
	 * @return
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() throws NoSuchAlgorithmException {
		if (privateKey instanceof RSAPrivateKey) {
			return EncryptionAlgorithm.RSA;
		} else if (privateKey instanceof DSAPrivateKey) {
			return EncryptionAlgorithm.DSA;
		} else if (privateKey instanceof ECPrivateKey) {
			return EncryptionAlgorithm.ECDSA;
		} else if (EncryptionAlgorithm.RSA.getName().equals(privateKey.getAlgorithm())) {
			return EncryptionAlgorithm.RSA;
		} else if (EncryptionAlgorithm.DSA.getName().equals(privateKey.getAlgorithm())) {
			return EncryptionAlgorithm.DSA;
		} else if (EncryptionAlgorithm.ECDSA.getName().equals(privateKey.getAlgorithm())) {
			return EncryptionAlgorithm.ECDSA;
		} else {
			throw new NoSuchAlgorithmException("Don't find algorithm for PrivateKey of type " + privateKey.getClass());
		}
	}

}
