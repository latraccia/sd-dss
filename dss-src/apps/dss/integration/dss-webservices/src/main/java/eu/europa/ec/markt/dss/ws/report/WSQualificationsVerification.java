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

import eu.europa.ec.markt.dss.validation.report.QualificationsVerification;

/**
 * Wrap a QualificationsVerification. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSQualificationsVerification {

    private String qcWithSSCD;
    private String qcNoSSCD;
    private String qcSSCDStatusAsInCert;
    private String qcForLegalPerson;

    /**
     * The default constructor for WSQualificationsVerification.
     */
    public WSQualificationsVerification() {
    }

    /**
     * 
     * The default constructor for WSQualificationsVerification.
     * 
     * @param verif
     */
    public WSQualificationsVerification(QualificationsVerification verif) {
        if (verif.getQCWithSSCD() != null) {
            qcWithSSCD = verif.getQCWithSSCD().getStatus().toString();
        }
        if (verif.getQCNoSSCD() != null) {
            qcNoSSCD = verif.getQCNoSSCD().getStatus().toString();
        }
        if (verif.getQCSSCDStatusAsInCert() != null) {
            qcSSCDStatusAsInCert = verif.getQCSSCDStatusAsInCert().getStatus().toString();
        }
        if (verif.getQCForLegalPerson() != null) {
            qcForLegalPerson = verif.getQCForLegalPerson().getStatus().toString();
        }
    }

    /**
     * @return the qcWithSSCD
     */
    public String getQcWithSSCD() {
        return qcWithSSCD;
    }

    /**
     * @param qcWithSSCD the qcWithSSCD to set
     */
    public void setQcWithSSCD(String qcWithSSCD) {
        this.qcWithSSCD = qcWithSSCD;
    }

    /**
     * @return the qcNoSSCD
     */
    public String getQcNoSSCD() {
        return qcNoSSCD;
    }

    /**
     * @param qcNoSSCD the qcNoSSCD to set
     */
    public void setQcNoSSCD(String qcNoSSCD) {
        this.qcNoSSCD = qcNoSSCD;
    }

    /**
     * @return the qcSSCDStatusAsInCert
     */
    public String getQcSSCDStatusAsInCert() {
        return qcSSCDStatusAsInCert;
    }

    /**
     * @param qcSSCDStatusAsInCert the qcSSCDStatusAsInCert to set
     */
    public void setQcSSCDStatusAsInCert(String qcSSCDStatusAsInCert) {
        this.qcSSCDStatusAsInCert = qcSSCDStatusAsInCert;
    }

    /**
     * @return the qcForLegalPerson
     */
    public String getQcForLegalPerson() {
        return qcForLegalPerson;
    }

    /**
     * @param qcForLegalPerson the qcForLegalPerson to set
     */
    public void setQcForLegalPerson(String qcForLegalPerson) {
        this.qcForLegalPerson = qcForLegalPerson;
    }

}
