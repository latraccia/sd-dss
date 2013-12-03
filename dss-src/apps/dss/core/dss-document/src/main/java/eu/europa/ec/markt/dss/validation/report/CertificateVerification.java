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

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.validation.CertificateStatus;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * 
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateVerification {

	@XmlElement
	private CertificateAndContext certificate;
	@XmlElement
	private Result validityPeriodVerification;
	@XmlElement
	private SignatureVerification signatureVerification;
	@XmlElement
	private RevocationVerificationResult certificateStatus;

	/**
	 * The default constructor for CertificateVerification.
	 */
	public CertificateVerification() {

	}

	/**
	 * 
	 * The default constructor for CertificateVerification.
	 * 
	 * @param cert
	 * @param ctx
	 */
	public CertificateVerification(CertificateAndContext cert, ValidationContext ctx) {

		certificate = cert;
		if (cert != null) {
			try {
				cert.getCertificate().checkValidity(ctx.getValidationDate());
				validityPeriodVerification = new Result(ResultStatus.VALID, null);
			} catch (CertificateExpiredException e) {
				validityPeriodVerification = new Result(ResultStatus.INVALID, "certificate.expired");
			} catch (CertificateNotYetValidException e) {
				validityPeriodVerification = new Result(ResultStatus.INVALID, "certificate.not.yet.valid");
			}

			CertificateStatus status = ctx.getCertificateStatusFromContext(cert);
			if (status != null) {
				certificateStatus = new RevocationVerificationResult(status);
			}
		}
	}

	/**
	 * @return the certificate
	 */
	public X509Certificate getCertificate() {
		return (certificate == null) ? null : certificate.getCertificate();
	}

	/**
	 * @return the validityPeriodVerification
	 */
	public Result getValidityPeriodVerification() {

		return validityPeriodVerification;
	}

	/**
	 * @return the signatureVerification
	 */
	public SignatureVerification getSignatureVerification() {

		return signatureVerification;
	}

	/**
	 * @return the certificateStatus
	 */
	public RevocationVerificationResult getCertificateStatus() {
		if (certificateStatus == null) {
			return new RevocationVerificationResult();
		}
		return certificateStatus;
	}

	/**
	 * this method may return the bare result that can be null
	 * 
	 * @return the certificateStatus
	 * @deprecated note that it is very likely that this method will be removed in the future!
	 */
	public RevocationVerificationResult getCertificateStatusUnchecked() {

		return certificateStatus;
	}

	/**
	 * @param certificate the certificate to set
	 */
	public void setCertificate(CertificateAndContext certificate) {

		this.certificate = certificate;
	}

	/**
	 * @param validityPeriodVerification the validityPeriodVerification to set
	 */
	public void setValidityPeriodVerification(Result validityPeriodVerification) {

		this.validityPeriodVerification = validityPeriodVerification;
	}

	/**
	 * @param signatureVerification the signatureVerification to set
	 */
	public void setSignatureVerification(SignatureVerification signatureVerification) {

		this.signatureVerification = signatureVerification;
	}

	/**
	 * @param signatureVerification the signatureVerification to set
	 */
	public void setSignatureVerification() {
		ResultStatus rs = (certificate != null && certificate.isSignatureOk()) ? ResultStatus.VALID : ResultStatus.INVALID;
		Result result = new Result();
		result.setStatus(rs, null);
		signatureVerification = new SignatureVerification(result, (certificate == null) ? null : certificate.getSignatureAlgorithm(), null);
	}

	/**
	 * @param certificateStatus the certificateStatus to set
	 */
	public void setCertificateStatus(RevocationVerificationResult certificateStatus) {

		this.certificateStatus = certificateStatus;
	}

	public String toString(String indentStr) {

		StringBuilder res = new StringBuilder();

		res.append(indentStr).append("[CertificateVerification\n");
		indentStr += "\t";

        if (certificate != null) {
            boolean aliases = true;
            if (aliases) {
                res.append(indentStr).append("Certificate: ").append(CertificateIdentifier.getId(getCertificate())).append("\n");
                res.append(indentStr).append("\tIssuer: ").append(CertificateIdentifier.getId(getCertificate())).append("\n");
            } else {
                if ( getCertificate() != null ) {
                    res.append(indentStr).append("Certificate: ").append(getCertificate().getSubjectDN().getName()).append("\n");
                    res.append(indentStr).append("\tIssuer: ").append(getCertificate().getIssuerDN().getName()).append("\n");
                }
            }
            res.append(indentStr).append("ValidityPeriodVerification: ").append(getValidityPeriodVerification()).append("\n");
            if (getSignatureVerification() != null) {
                res.append(getSignatureVerification().toString(indentStr));
            }
            res.append(indentStr).append("CertificateSource: ").append(certificate.getCertificateSource()).append("\n");
        }

		res.append(getCertificateStatus().toString(indentStr));

		indentStr = indentStr.substring(1);
		res.append(indentStr).append("]\n");

		return res.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}
}
