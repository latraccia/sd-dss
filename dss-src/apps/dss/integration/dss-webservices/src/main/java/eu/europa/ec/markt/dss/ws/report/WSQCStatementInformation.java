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

import eu.europa.ec.markt.dss.validation.report.QCStatementInformation;

/**
 * Wrap a QCStatementInformation. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSQCStatementInformation {

    private String qcPPresent;
    private String qcPPlusPresent;
    private String qcCompliancePresent;
    private String qcSCCDPresent;

    /**
     * The default constructor for WSQCStatementInformation.
     */
    public WSQCStatementInformation() {
    }

    /**
     * The default constructor for WSQCStatementInformation.
     */
    public WSQCStatementInformation(QCStatementInformation info) {
        if (info.getQCPPresent() != null) {
            qcPPresent = info.getQCPPresent().getStatus().toString();
        }
        if (info.getQCPPlusPresent() != null) {
            qcPPlusPresent = info.getQCPPlusPresent().getStatus().toString();
        }
        if (info.getQcCompliancePresent() != null) {
            qcCompliancePresent = info.getQcCompliancePresent().getStatus().toString();
        }
        if (info.getQcSCCDPresent() != null) {
            qcSCCDPresent = info.getQcSCCDPresent().getStatus().toString();
        }
    }

    /**
     * @return the qcPPresent
     */
    public String getQcPPresent() {
        return qcPPresent;
    }

    /**
     * @param qcPPresent the qcPPresent to set
     */
    public void setQcPPresent(String qcPPresent) {
        this.qcPPresent = qcPPresent;
    }

    /**
     * @return the qcPPlusPresent
     */
    public String getQcPPlusPresent() {
        return qcPPlusPresent;
    }

    /**
     * @param qcPPlusPresent the qcPPlusPresent to set
     */
    public void setQcPPlusPresent(String qcPPlusPresent) {
        this.qcPPlusPresent = qcPPlusPresent;
    }

    /**
     * @return the qcCompliancePresent
     */
    public String getQcCompliancePresent() {
        return qcCompliancePresent;
    }

    /**
     * @param qcCompliancePresent the qcCompliancePresent to set
     */
    public void setQcCompliancePresent(String qcCompliancePresent) {
        this.qcCompliancePresent = qcCompliancePresent;
    }

    /**
     * @return the qcSCCDPresent
     */
    public String getQcSCCDPresent() {
        return qcSCCDPresent;
    }

    /**
     * @param qcSCCDPresent the qcSCCDPresent to set
     */
    public void setQcSCCDPresent(String qcSCCDPresent) {
        this.qcSCCDPresent = qcSCCDPresent;
    }

}
