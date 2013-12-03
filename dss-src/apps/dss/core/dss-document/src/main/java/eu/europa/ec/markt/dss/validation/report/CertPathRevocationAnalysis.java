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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import eu.europa.ec.markt.dss.validation.CertificateValidity;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;
import eu.europa.ec.markt.dss.validation.tsl.QualificationElement;

/**
 * Validation information for a Certificate Path (from an end user certificate to the Trusted List)
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class CertPathRevocationAnalysis {

	@XmlElement
	private Result summary;
	@XmlElement
	private List<CertificateVerification> certificatePathVerification = new ArrayList<CertificateVerification>();
	@XmlElement
	private TrustedListInformation trustedListInformation;

	public CertPathRevocationAnalysis() {

	}

	/**
	 * 
	 * The default constructor for CertPathRevocationAnalysis.
	 * 
	 * @param ctx
	 * @param info
	 */
	public CertPathRevocationAnalysis(ValidationContext ctx, TrustedListInformation info) {

		summary = new Result();
		this.trustedListInformation = info;

		if (ctx != null) {

			for (CertificateAndContext cert : ctx.getNeededCertificates()) {

				certificatePathVerification.add(new CertificateVerification(cert, ctx));
			}
		}

		summary.setStatus(ResultStatus.VALID, null);
		for (CertificateVerification verif : certificatePathVerification) {

			verif.setSignatureVerification();
			if (verif.getValidityPeriodVerification().isInvalid()) {

				summary.setStatus(ResultStatus.INVALID, "certificate.not.valid");
				break;
			}
			CertificateValidity certValidity = verif.getCertificateStatus().getStatus();
			if (certValidity.equals(CertificateValidity.REVOKED)) {

				summary.setStatus(ResultStatus.INVALID, "certificate.revoked");
				break;
			} else if (certValidity.equals(CertificateValidity.UNKNOWN) || certValidity == null) {

				summary.setStatus(ResultStatus.UNDETERMINED, "revocation.unknown");
			}
		}
		if (trustedListInformation != null) {

			if (!trustedListInformation.isServiceWasFound()) {

				summary.setStatus(ResultStatus.INVALID, "no.trustedlist.service.was.found");
			}
		} else {

			summary.setStatus(ResultStatus.INVALID, "no.trustedlist.service.was.found");
		}
	}

	/**
	 * @return the summary
	 */
	public Result getSummary() {

		return summary;
	}

	/**
	 * @return the certificatePathVerification
	 */
	public List<CertificateVerification> getCertificatePathVerification() {

		return certificatePathVerification;
	}

	/**
	 * @return the trustedListInformation
	 */
	public TrustedListInformation getTrustedListInformation() {

		return trustedListInformation;
	}

	/**
	 * @param summary the summary to set
	 */
	public void setSummary(Result summary) {

		this.summary = summary;
	}

	/**
	 * @param certificatePathVerification the certificatePathVerification to set
	 */
	public void setCertificatePathVerification(List<CertificateVerification> certificatePathVerification) {

		this.certificatePathVerification = certificatePathVerification;
	}

	/**
	 * @param trustedListInformation the trustedListInformation to set
	 */
	public void setTrustedListInformation(TrustedListInformation trustedListInformation) {

		this.trustedListInformation = trustedListInformation;
	}

	public String toString(String indentStr) {
		StringBuilder res = new StringBuilder();

		res.append(indentStr).append("[CertPathRevocationAnalysis\n");
		indentStr += "\t";

        res.append(indentStr).append("Summary: ").append((getSummary() == null) ? null : getSummary().getStatus()).append("\n");
        if ( getCertificatePathVerification() != null ) {
            for (CertificateVerification cv : getCertificatePathVerification()) {
                res.append((cv == null) ? null : cv.toString(indentStr));
            }
        }
		TrustedListInformation tli = getTrustedListInformation();
        if ( tli != null ) {
            res.append(indentStr).append("ServiceWasFound: ").append(tli.isServiceWasFound()).append("\n");
            res.append(indentStr).append("TSPName: ").append(tli.getTSPName()).append("\n");
            res.append(indentStr).append("TSPTradeName: ").append(tli.getTSPTradeName()).append("\n");
            res.append(indentStr).append("TSPPostalAddress: ").append(tli.getTSPPostalAddress()).append("\n");
            res.append(indentStr).append("TSPElectronicAddress: ").append(tli.getTSPElectronicAddress()).append("\n");
            res.append("\n");
            res.append(indentStr).append("ServiceType: ").append(tli.getServiceType()).append("\n");
            res.append(indentStr).append("ServiceName: ").append(tli.getServiceName()).append("\n");
            res.append(indentStr).append("CurrentStatus: ").append(tli.getCurrentStatus()).append("\n");
            res.append(indentStr).append("CurrentStatusStartingDate: ").append(tli.getCurrentStatusStartingDate()).append("\n");
            // The same like CurrentStatusStartingDate
            // res.append(indentStr).append("StatusStartingDateAtReferenceTime: ").append(tli.getStatusStartingDateAtReferenceTime()).append("\n");
            res.append(indentStr).append("StatusAtReferenceTime: ").append(tli.getStatusAtReferenceTime()).append("\n");
            if ( tli.getQualificationElements() != null) {
                for (QualificationElement qe : tli.getQualificationElements() ) {
                    res.append((qe == null) ? null : qe.toString(indentStr));
                }
            }
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
