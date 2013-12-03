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
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;

/**
 * Condition that check a specific QCStatement
 * 
 * 
 * @version $Revision: 2020 $ - $Date: 2013-05-16 07:54:22 +0200 (jeu., 16 mai 2013) $
 */

public class QcStatementCondition implements Condition, Serializable {

	private static final long serialVersionUID = -5504958938057542907L;

	private String qcStatementId = null;

	/**
	 * Mandatory for serializable
	 */
	public QcStatementCondition() {
	}

	/**
	 * 
	 * The default constructor for QcStatementCondition.
	 * 
	 * @param qcStatementId
	 */
	public QcStatementCondition(String qcStatementId) {
		this.qcStatementId = qcStatementId;
	}

	/**
	 * 
	 * The default constructor for QcStatementCondition.
	 * 
	 * @param qcStatementId
	 */
	public QcStatementCondition(DERObjectIdentifier qcStatementId) {
		this(qcStatementId.getId());
	}

	@Override
	public boolean check(CertificateAndContext cert) {

		// Bob (20130516) deprecated:byte[] qcStatement =
		// cert.getCertificate().getExtensionValue(X509Extensions.QCStatements.getId());
		byte[] qcStatement = cert.getCertificate().getExtensionValue(X509Extension.qCStatements.getId());
		if (qcStatement != null) {

			try {

				ASN1InputStream input = new ASN1InputStream(qcStatement);
				DEROctetString s = (DEROctetString) input.readObject();
				input.close();
				byte[] content = s.getOctets();
				input = new ASN1InputStream(content);
				DERSequence seq = (DERSequence) input.readObject();
				input.close();
				/* Sequence of QCStatment */
				for (int i = 0; i < seq.size(); i++) {

					QCStatement statement = QCStatement.getInstance(seq.getObjectAt(i));
					if (statement.getStatementId().getId().equals(qcStatementId)) {

						return true;
					}
				}
				return false;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return false;
	}
}
