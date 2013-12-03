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

import eu.europa.ec.markt.dss.validation.report.SignatureVerification;

/**
 * Contains information about the validity of a signature. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSSignatureVerification {

    private String signatureVerificationResult;
    private String signatureAlgorithm;

    /**
     * The default constructor for WSSignatureVerification.
     */
    public WSSignatureVerification() {
    }

    /**
     * 
     * The default constructor for WSSignatureVerification.
     * 
     * @param verif
     */
    public WSSignatureVerification(SignatureVerification verif) {
        if (verif.getSignatureVerificationResult() != null) {
            signatureVerificationResult = verif.getSignatureVerificationResult().getStatus().toString();
        }
        signatureAlgorithm = verif.getSignatureAlgorithm();
    }

    /**
     * @return the signatureVerificationResult
     */
    public String getSignatureVerificationResult() {
        return signatureVerificationResult;
    }

    /**
     * @param signatureVerificationResult the signatureVerificationResult to set
     */
    public void setSignatureVerificationResult(String signatureVerificationResult) {
        this.signatureVerificationResult = signatureVerificationResult;
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

}
