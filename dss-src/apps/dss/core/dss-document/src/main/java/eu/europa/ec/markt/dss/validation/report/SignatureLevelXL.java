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

import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;

/**
 * Validation information for level XL (CAdES, XAdES).
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureLevelXL extends SignatureLevel {
    @XmlElement
    private Result certificateValuesVerification;
    @XmlElement
    private Result revocationValuesVerification;

    public SignatureLevelXL() {
        super();
    }

    /**
     * The default constructor for SignatureLevelBES.
     * 
     * @param name
     * @param signature
     * @param levelReached
     */
    public SignatureLevelXL(Result levelReached, Result certificateValuesVerification, Result revocationValuesVerification) {
        super(levelReached);

        this.certificateValuesVerification = certificateValuesVerification;
        this.revocationValuesVerification = revocationValuesVerification;
    }

    /**
     * @return the certificateRefsVerification
     */
    public Result getCertificateValuesVerification() {
        return certificateValuesVerification;
    }

    /**
     * @return the revocationRefsVerification
     */
    public Result getRevocationValuesVerification() {
        return revocationValuesVerification;
    }

    public String toString(String indentStr) {
        if ( getLevelReached() == null ) {
            return "";
        }
        ResultStatus status = getLevelReached().getStatus();
        if (status == null  || (!status.equals(ResultStatus.VALID) && !status.equals(ResultStatus.INVALID))) {
            return "";
        }

        StringBuilder res = new StringBuilder();

        res.append(indentStr).append("[Level XL\r\n");
        indentStr += "\t";

        res.append(indentStr).append("LevelReached: ").append(status).append("\r\n");
        res.append(indentStr).append("CertificateValuesVerification: ").append((getCertificateValuesVerification() == null) ? null : getCertificateValuesVerification().getStatus()).append("\r\n");
        res.append(indentStr).append("RevocationValuesVerification: ").append(getRevocationValuesVerification()).append("\r\n");

        indentStr = indentStr.substring(1);
        res.append(indentStr).append("]\r\n");

        return res.toString();
    }

    @Override
    public String toString() {
        return toString("");
    }
}
