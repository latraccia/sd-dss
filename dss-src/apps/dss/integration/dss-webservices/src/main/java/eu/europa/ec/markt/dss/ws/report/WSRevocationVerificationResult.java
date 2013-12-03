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

import eu.europa.ec.markt.dss.validation.report.RevocationVerificationResult;

import java.util.Date;

/**
 * Representation of a certificate status, used to indicate the success or the failure of the verification of revocation
 * data.  Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSRevocationVerificationResult {

    private String status;

    private Date revocationDate;

    private String issuer;

    private Date issuingTime;

    /**
     * The default constructor for WSRevocationVerificationResult.
     */
    public WSRevocationVerificationResult() {
    }

    /**
     * 
     * The default constructor for WSRevocationVerificationResult.
     * 
     * @param result
     */
    public WSRevocationVerificationResult(RevocationVerificationResult result) {
        if (result.getStatus() != null) {
            status = result.getStatus().toString();
        }
        revocationDate = result.getRevocationDate();
        issuer = result.getIssuer();
        issuingTime = result.getIssuingTime();
    }

    /**
     * @return the status
     */
    public String getStatus() {
        return status;
    }

    /**
     * @param status the status to set
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * @return the revocationDate
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * @param revocationDate the revocationDate to set
     */
    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    /**
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * @param issuer the issuer to set
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the issuingTime
     */
    public Date getIssuingTime() {
        return issuingTime;
    }

    /**
     * @param issuingTime the issuingTime to set
     */
    public void setIssuingTime(Date issuingTime) {
        this.issuingTime = issuingTime;
    }

}
