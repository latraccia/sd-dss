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

import eu.europa.ec.markt.dss.validation.report.CertPathRevocationAnalysis;
import eu.europa.ec.markt.dss.validation.report.CertificateVerification;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrap a CertPathRevocationAnalysis. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSCertPathRevocationAnalysis {

    private String summary;
    private List<WSCertificateVerification> certificatePathVerification = new ArrayList<WSCertificateVerification>();
    private WSTrustedListInformation trustedListInformation;

    /**
     * The default constructor for WSCertPathRevocationAnalysis.
     */
    public WSCertPathRevocationAnalysis() {
    }

    /**
     * 
     * The default constructor for WSCertPathRevocationAnalysis.
     * 
     * @param analysis
     */
    public WSCertPathRevocationAnalysis(CertPathRevocationAnalysis analysis) {
        if (analysis.getSummary() != null) {
            summary = analysis.getSummary().getStatus().toString();
        }
        certificatePathVerification = new ArrayList<WSCertificateVerification>();
        if (analysis.getCertificatePathVerification() != null) {
            for (CertificateVerification v : analysis.getCertificatePathVerification()) {
                certificatePathVerification.add(new WSCertificateVerification(v));
            }
        }
        if (analysis.getTrustedListInformation() != null) {
            trustedListInformation = new WSTrustedListInformation(analysis.getTrustedListInformation());
        }
    }

    /**
     * @return the summary
     */
    public String getSummary() {
        return summary;
    }

    /**
     * @param summary the summary to set
     */
    public void setSummary(String summary) {
        this.summary = summary;
    }

    /**
     * @return the certificatePathVerification
     */
    public List<WSCertificateVerification> getCertificatePathVerification() {
        return certificatePathVerification;
    }

    /**
     * @param certificatePathVerification the certificatePathVerification to set
     */
    public void setCertificatePathVerification(List<WSCertificateVerification> certificatePathVerification) {
        this.certificatePathVerification = certificatePathVerification;
    }

    /**
     * @return the trustedListInformation
     */
    public WSTrustedListInformation getTrustedListInformation() {
        return trustedListInformation;
    }

    /**
     * @param trustedListInformation the trustedListInformation to set
     */
    public void setTrustedListInformation(WSTrustedListInformation trustedListInformation) {
        this.trustedListInformation = trustedListInformation;
    }

}
