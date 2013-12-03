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

import java.util.Date;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

/**
 * Validation information of a timestamp.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class TimestampVerificationResult {
    @XmlElement
    private Result sameDigest;
    @XmlElement
    private Result certPathVerification = new Result();
    @XmlElement
    private String signatureAlgorithm;
    @XmlElement
    private String serialNumber;
    @XmlElement
    private Date creationTime;
    @XmlElement
    private String issuerName;

    /**
     * The default constructor for TimestampVerificationResult.
     */
    public TimestampVerificationResult() {
    }

    /**
     * The default constructor for TimestampVerificationResult.
     */
    public TimestampVerificationResult(TimestampToken token) {

        if (token != null && token.getTimeStamp() != null) {

            signatureAlgorithm = ((SignerInformation) token.getTimeStamp().toCMSSignedData().getSignerInfos().getSigners().iterator().next())
                    .getEncryptionAlgOID();
            serialNumber = token.getTimeStamp().getTimeStampInfo().getSerialNumber().toString();
            creationTime = token.getTimeStamp().getTimeStampInfo().getGenTime();
            issuerName = token.getSignerSubjectName().toString();
        }
    }

    /**
     * @param sameDigest the sameDigest to set
     */
    public void setSameDigest(Result sameDigest) {
        this.sameDigest = sameDigest;
    }

    /**
     * @return the sameDigest
     */
    public Result getSameDigest() {
        return sameDigest;
    }

    /**
     * 
     * @return
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * 
     * @return
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * 
     * @return
     */
    public Date getCreationTime() {
        return creationTime;
    }

    /**
     * 
     * @return
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * 
     * @return
     */
    public Result getCertPathUpToTrustedList() {
        return certPathVerification;
    }

    /**
     * @return the certPathVerification
     */
    public Result getCertPathVerification() {
        return certPathVerification;
    }

    /**
     * @param certPathVerification the certPathVerification to set
     */
    public void setCertPathVerification(Result certPathVerification) {
        this.certPathVerification = certPathVerification;
    }

    /**
     * @param signatureAlgorithm the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @param serialNumber the serialNumber to set
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @param creationTime the creationTime to set
     */
    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * @param issuerName the issuerName to set
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public String toString(String indentStr) {
        StringBuilder res = new StringBuilder();

        indentStr += "\t";

        res.append(indentStr).append("SameDigest: ").append(getSameDigest()).append("\r\n");
        res.append(indentStr).append("SerialNumber: ").append(getSerialNumber()).append("\r\n");
        res.append(indentStr).append("CreationTime: ").append(getCreationTime()).append("\r\n");
        res.append(indentStr).append("IssuerName: ").append(getIssuerName()).append("\r\n");
        res.append(indentStr).append("CertPathUpToTrustedList: ").append(getCertPathUpToTrustedList()).append("\r\n");
        res.append(indentStr).append("CertPathVerification: ").append(getCertPathVerification()).append("\r\n");

        indentStr = indentStr.substring(1);
        return res.toString();
    }

    @Override
    public String toString() {
        return toString("");
    }
}
