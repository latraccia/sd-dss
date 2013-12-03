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

package eu.europa.ec.markt.dss.validation.report;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Contains information about the validity of a signature.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureVerification {

	@XmlElement
	private Result signatureVerificationResult;
	@XmlElement
	private String signatureAlgorithm;

	private String id;

	public SignatureVerification() {

	}

	/**
	 * The default constructor for SignatureVerification.
	 */
	public SignatureVerification(Result signatureVerificationResult, String signatureAlgorithm, String id) {

		this.signatureVerificationResult = signatureVerificationResult;
		this.signatureAlgorithm = signatureAlgorithm;
		this.id = id;
	}

	/**
	 * specifies if the signature is mathematically correct or not
	 * 
	 * @return the signature verification result
	 */
	public Result getSignatureVerificationResult() {

		return signatureVerificationResult;
	}

	/**
	 * Provides the name of the algorithm applied for the signature
	 * 
	 * @return the signature algorithm
	 */
	public String getSignatureAlgorithm() {

		return signatureAlgorithm;
	}

	public String getId() {

		return id;
	}

	public String toString(String indentStr) {
		StringBuilder res = new StringBuilder();

        res.append(indentStr).append("[SignatureVerification\n");
		indentStr += "\t";

		if (getId() != null) {
			res.append(indentStr).append("Id: ").append(getId()).append("\n");
		}
		res.append(indentStr).append("Result: ").append((getSignatureVerificationResult() == null)? null : getSignatureVerificationResult().getStatus()).append("\n");
		res.append(indentStr).append("SignatureAlgorithm: ").append(getSignatureAlgorithm()).append("\n");

        indentStr = indentStr.substring(1);
		res.append(indentStr).append("]\n");

        return res.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}
}
