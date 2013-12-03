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

package eu.europa.ec.markt.dss.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Represent the value of a SignaturePolicy
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyValue {
	@XmlElement
	private String signaturePolicyId;

	@XmlElement
	private String commitmentTypeIndication;

	/**
	 * 
	 * The default constructor for PolicyValue.
	 * 
	 * @param signaturePolicyId
	 */
	public PolicyValue(String signaturePolicyId) {
		this.signaturePolicyId = signaturePolicyId;
	}

	/**
	 * The default constructor for PolicyValue.
	 */
	public PolicyValue() {
		this.signaturePolicyId = "";
	}

	/**
	 * @return the signaturePolicyId
	 */
	public String getSignaturePolicyId() {
		return signaturePolicyId;
	}

	@Override
	public String toString() {
		if (signaturePolicyId == null) {
			return "NO_POLICY";
		} else if (signaturePolicyId.equals("")) {
			return "IMPLICIT";
		} else {
			return signaturePolicyId;
		}
    }

}
