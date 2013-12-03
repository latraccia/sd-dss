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

package eu.europa.ec.markt.dss.ws.report;

import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;

import java.util.Date;

/**
 * Wrap data of a TimestampVerfificationResult. Used to expose the information in the Webservice. Used to expose the
 * information in the Webservice.
 * 
 * 
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSTimestampVerificationResult {

    private String sameDigest;
    private String certPathVerification;
    private String signatureAlgorithm;
    private String serialNumber;
    private Date creationTime;
    private String issuerName;

    /**
     * The default constructor for WSTimestampVerificationResult.
     */
    public WSTimestampVerificationResult() {
    }

    /**
     * 
     * The default constructor for WSTimestampVerificationResult.
     * 
     * @param result
     */
    public WSTimestampVerificationResult(TimestampVerificationResult result) {
        if (result.getSameDigest() != null) {
            sameDigest = result.getSameDigest().getStatus().toString();
        }
        if (result.getCertPathUpToTrustedList() != null) {
            certPathVerification = result.getCertPathUpToTrustedList().getStatus().toString();
        }
        signatureAlgorithm = result.getSignatureAlgorithm();
        serialNumber = result.getSerialNumber();
        creationTime = result.getCreationTime();
        issuerName = result.getIssuerName();
    }

    /**
     * @return the sameDigest
     */
    public String getSameDigest() {
        return sameDigest;
    }

    /**
     * @param sameDigest the sameDigest to set
     */
    public void setSameDigest(String sameDigest) {
        this.sameDigest = sameDigest;
    }

    /**
     * @return the certPathVerification
     */
    public String getCertPathVerification() {
        return certPathVerification;
    }

    /**
     * @param certPathVerification the certPathVerification to set
     */
    public void setCertPathVerification(String certPathVerification) {
        this.certPathVerification = certPathVerification;
    }

    /**
     * @return the signatureAlgorithm
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber the serialNumber to set
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the creationTime
     */
    public Date getCreationTime() {
        return creationTime;
    }

    /**
     * @param creationTime the creationTime to set
     */
    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName the issuerName to set
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

}
