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

import eu.europa.ec.markt.dss.validation.report.CertificateVerification;

import java.security.cert.CertificateEncodingException;

/**
 * Wrap data of a CertificateVerification.  Used to expose the information in the Webservice. 
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSCertificateVerification {

    private byte[] certificate;
    private String validityPeriodVerification;
    private WSSignatureVerification signatureVerification;
    private WSRevocationVerificationResult certificateStatus;

    /**
     * The default constructor for WSCertificateVerification.
     */
    public WSCertificateVerification() {
    }

    /**
     * The default constructor for WSCertificateVerification.
     */
    public WSCertificateVerification(CertificateVerification c) {
        if (c.getCertificate() != null) {
            try {
                certificate = c.getCertificate().getEncoded();
            } catch (CertificateEncodingException e) {
                // Should never happens
                throw new RuntimeException(e);
            }
        }
        if (c.getValidityPeriodVerification() != null) {
            validityPeriodVerification = c.getValidityPeriodVerification().getStatus().toString();
        }
    }

    /**
     * @return the certificate
     */
    public byte[] getCertificate() {
        return certificate;
    }

    /**
     * @param certificate the certificate to set
     */
    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    /**
     * @return the validityPeriodVerification
     */
    public String getValidityPeriodVerification() {
        return validityPeriodVerification;
    }

    /**
     * @param validityPeriodVerification the validityPeriodVerification to set
     */
    public void setValidityPeriodVerification(String validityPeriodVerification) {
        this.validityPeriodVerification = validityPeriodVerification;
    }

    /**
     * @return the signatureVerification
     */
    public WSSignatureVerification getSignatureVerification() {
        return signatureVerification;
    }

    /**
     * @param signatureVerification the signatureVerification to set
     */
    public void setSignatureVerification(WSSignatureVerification signatureVerification) {
        this.signatureVerification = signatureVerification;
    }

    /**
     * @return the certificateStatus
     */
    public WSRevocationVerificationResult getCertificateStatus() {
        return certificateStatus;
    }

    /**
     * @param certificateStatus the certificateStatus to set
     */
    public void setCertificateStatus(WSRevocationVerificationResult certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

}
