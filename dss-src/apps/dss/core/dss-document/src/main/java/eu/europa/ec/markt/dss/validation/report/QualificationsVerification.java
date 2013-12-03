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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Qualification of the certificate according to the QualificationElement of the Trusted List.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class QualificationsVerification {
    @XmlElement
    private Result QCWithSSCD;
    @XmlElement
    private Result QCNoSSCD;
    @XmlElement
    private Result QCSSCDStatusAsInCert;
    @XmlElement
    private Result QCForLegalPerson;

    public QualificationsVerification() {
    }

    /**
     * @return the qCWithSSCD
     */
    public Result getQCWithSSCD() {
        return QCWithSSCD;
    }

    /**
     * @return the qCNoSSCD
     */
    public Result getQCNoSSCD() {
        return QCNoSSCD;
    }

    /**
     * @return the qCSSCDStatusAsInCert
     */
    public Result getQCSSCDStatusAsInCert() {
        return QCSSCDStatusAsInCert;
    }

    /**
     * @return the qCForLegalPerson
     */
    public Result getQCForLegalPerson() {
        return QCForLegalPerson;
    }

    /**
     * The default constructor for QualificationExtensionAnalysis.
     * 
     * @param qCWithSSCD
     * @param qCNoSSCD
     * @param qCSSCDStatusAsInCert
     * @param qCForLegalPerson
     */
    public QualificationsVerification(Result qCWithSSCD, Result qCNoSSCD, Result qCSSCDStatusAsInCert, Result qCForLegalPerson) {
        QCWithSSCD = qCWithSSCD;
        QCNoSSCD = qCNoSSCD;
        QCSSCDStatusAsInCert = qCSSCDStatusAsInCert;
        QCForLegalPerson = qCForLegalPerson;
    }

    public String toString(String indentStr) {
        StringBuilder res = new StringBuilder();

        res.append(indentStr).append("[QualificationsVerification\r\n");
        indentStr += "\t";

        res.append(indentStr).append("QCWithSSCD: ").append((getQCWithSSCD() == null) ? null : getQCWithSSCD().getStatus()).append("\r\n");
        res.append(indentStr).append("QCNoSSCD: ").append((getQCNoSSCD() == null) ? null : getQCNoSSCD().getStatus()).append("\r\n");
        res.append(indentStr).append("QCSSCDStatusAsInCert: ").append((getQCSSCDStatusAsInCert() == null) ? null : getQCSSCDStatusAsInCert().getStatus()).append("\r\n");
        res.append(indentStr).append("QCForLegalPerson: ").append((getQCForLegalPerson() == null) ? null : getQCForLegalPerson().getStatus()).append("\r\n");

        indentStr = indentStr.substring(1);
        res.append(indentStr).append("]\r\n");

        return res.toString();
    }

    @Override
    public String toString() {
        return toString("");
    }
}
