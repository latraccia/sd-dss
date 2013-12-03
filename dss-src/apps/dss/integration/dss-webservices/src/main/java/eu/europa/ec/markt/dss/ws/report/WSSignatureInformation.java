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

import eu.europa.ec.markt.dss.validation.report.SignatureInformation;

/**
 * Wrap a SignatureInformation data. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSSignatureInformation {

    private WSSignatureVerification signatureVerification;
    private WSCertPathRevocationAnalysis certPathRevocationAnalysis;
    private WSSignatureLevelAnalysis signatureLevelAnalysis;
    private WSQualificationsVerification qualificationsVerification;
    private WSQCStatementInformation qcStatementInformation;
    private String finalConclusion;

    /**
     * The default constructor for WSSignatureInformation.
     */
    public WSSignatureInformation() {
    }

    /**
     * The default constructor for WSSignatureInformation.
     */
    public WSSignatureInformation(SignatureInformation info) {
        if (info.getSignatureVerification() != null) {
            signatureVerification = new WSSignatureVerification(info.getSignatureVerification());
        }
        if (info.getCertPathRevocationAnalysis() != null) {
            certPathRevocationAnalysis = new WSCertPathRevocationAnalysis(info.getCertPathRevocationAnalysis());
        }
        if (info.getSignatureLevelAnalysis() != null) {
            signatureLevelAnalysis = new WSSignatureLevelAnalysis(info.getSignatureLevelAnalysis());
        }
        if (info.getQualificationsVerification() != null) {
            qualificationsVerification = new WSQualificationsVerification(info.getQualificationsVerification());
        }
        if (info.getQcStatementInformation() != null) {
            qcStatementInformation = new WSQCStatementInformation(info.getQcStatementInformation());
        }
        if (info.getFinalConclusion() != null) {
            finalConclusion = info.getFinalConclusion().toString();
        }
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
     * @return the certPathRevocationAnalysis
     */
    public WSCertPathRevocationAnalysis getCertPathRevocationAnalysis() {
        return certPathRevocationAnalysis;
    }

    /**
     * @param certPathRevocationAnalysis the certPathRevocationAnalysis to set
     */
    public void setCertPathRevocationAnalysis(WSCertPathRevocationAnalysis certPathRevocationAnalysis) {
        this.certPathRevocationAnalysis = certPathRevocationAnalysis;
    }

    /**
     * @return the signatureLevelAnalysis
     */
    public WSSignatureLevelAnalysis getSignatureLevelAnalysis() {
        return signatureLevelAnalysis;
    }

    /**
     * @param signatureLevelAnalysis the signatureLevelAnalysis to set
     */
    public void setSignatureLevelAnalysis(WSSignatureLevelAnalysis signatureLevelAnalysis) {
        this.signatureLevelAnalysis = signatureLevelAnalysis;
    }

    /**
     * @return the qualificationsVerification
     */
    public WSQualificationsVerification getQualificationsVerification() {
        return qualificationsVerification;
    }

    /**
     * @param qualificationsVerification the qualificationsVerification to set
     */
    public void setQualificationsVerification(WSQualificationsVerification qualificationsVerification) {
        this.qualificationsVerification = qualificationsVerification;
    }

    /**
     * @return the qcStatementInformation
     */
    public WSQCStatementInformation getQcStatementInformation() {
        return qcStatementInformation;
    }

    /**
     * @param qcStatementInformation the qcStatementInformation to set
     */
    public void setQcStatementInformation(WSQCStatementInformation qcStatementInformation) {
        this.qcStatementInformation = qcStatementInformation;
    }

    /**
     * @return the finalConclusion
     */
    public String getFinalConclusion() {
        return finalConclusion;
    }

    /**
     * @param finalConclusion the finalConclusion to set
     */
    public void setFinalConclusion(String finalConclusion) {
        this.finalConclusion = finalConclusion;
    }

}
