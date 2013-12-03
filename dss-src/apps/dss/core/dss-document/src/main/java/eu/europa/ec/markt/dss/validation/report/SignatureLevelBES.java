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

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.adapter.X509CertificateAdapter;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;

/**
 * Validation information for level BES
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureLevelBES extends SignatureLevel {

	@XmlJavaTypeAdapter(X509CertificateAdapter.class)
	private X509Certificate signingCertificate;
	@XmlElement
	private Result signingCertRefVerification;
	@XmlElement
	private SignatureVerification[] counterSignaturesVerification;
	@XmlElement
	private List<TimestampVerificationResult> timestampsVerification;
	@XmlJavaTypeAdapter(X509CertificateAdapter.class)
	private List<X509Certificate> certificates;
	@XmlElement
	private Date signingTime;
	@XmlElement
	private String location;
	@XmlElement
	private String[] claimedSignerRole;
	@XmlElement
	private String contentType;

	public SignatureLevelBES() {

		super();
	}

	/**
	 * The default constructor for SignatureLevelBES.
	 * 
	 * @param name
	 * @param signature
	 * @param levelReached
	 */
	public SignatureLevelBES(Result levelReached, AdvancedSignature signature, Result signingCertificateVerification,
			SignatureVerification[] counterSignatureVerification, List<TimestampVerificationResult> timestampsVerification) {

		super(levelReached);

		this.signingCertRefVerification = signingCertificateVerification;
		this.counterSignaturesVerification = counterSignatureVerification;
		this.timestampsVerification = timestampsVerification;

		if (signature != null) {
			certificates = signature.getCertificates();
			signingCertificate = signature.getSigningCertificate();
			signingTime = signature.getSigningTime();
			location = signature.getLocation();
			claimedSignerRole = signature.getClaimedSignerRoles();
			contentType = signature.getContentType();
		}
	}

	/**
	 * @return the signingCertificateVerification
	 */
	public Result getSigningCertRefVerification() {

		return signingCertRefVerification;
	}

	/**
	 * @return the counterSignaturesVerification
	 */
	public SignatureVerification[] getCounterSignaturesVerification() {

		return counterSignaturesVerification;
	}

	/**
	 * @return the timestampsVerification
	 */
	public List<TimestampVerificationResult> getTimestampsVerification() {

		return timestampsVerification;
	}

	/* Delegate methods for the provided AdvancedSignature */

	/**
	 * @return
	 * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getCertificates()
	 */
	public List<X509Certificate> getCertificates() {

		return certificates;
	}

	/**
	 * @return
	 * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getLocation()
	 */
	public String getLocation() {

		return location;
	}

	/**
	 * @return
	 * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getContentType()
	 */
	public String getContentType() {

		return contentType;
	}

	/**
	 * @return
	 * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getClaimedSignerRoles()
	 */
	public String[] getClaimedSignerRoles() {

		return claimedSignerRole;
	}

	/**
	 * 
	 * @return
	 */
	public X509Certificate getSigningCertificate() {

		return signingCertificate;
	}

	/**
	 * The signing time of this signature
	 * 
	 * @return
	 */
	public Date getSigningTime() {

		return signingTime;
	}

	public String toString(String indentStr) {
		StringBuilder res = new StringBuilder();

		res.append(indentStr).append("[Level BES\n");
		indentStr += "\t";

        res.append(indentStr).append("LevelReached: ").append((getLevelReached() == null) ? null : getLevelReached().isValid()).append("\n");
		res.append(indentStr).append("SigningCertificate SubjectDN: ").append(CertificateIdentifier.getId(getSigningCertificate())).append("\n");
		res.append(indentStr).append("[Certificate chain\n");
        if ( getCertificates() != null ) {
            indentStr += "\t";
            for (X509Certificate c : getCertificates()) {
                res.append(indentStr).append("Certificate SubjectDN: ").append(CertificateIdentifier.getId(c)).append("\n");
            }
            indentStr = indentStr.substring(1);
        }
		res.append(indentStr).append("]\n");
		res.append(indentStr).append("SigningCertRefVerification: ").append((getSigningCertRefVerification() == null) ? null : getSigningCertRefVerification().getStatus()).append("\n");
        if ( getCounterSignaturesVerification() != null ) {
            res.append(indentStr).append("[CounterSignaturesVerification\n");
            indentStr += "\t";
            for (SignatureVerification sv : getCounterSignaturesVerification()) {
                res.append((sv == null) ? null : sv.toString(indentStr));
            }
            indentStr = indentStr.substring(1);
            res.append(indentStr).append("]\n");
        }

		indentStr = indentStr.substring(1);
		res.append(indentStr).append("]\n");

		return res.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}

}
