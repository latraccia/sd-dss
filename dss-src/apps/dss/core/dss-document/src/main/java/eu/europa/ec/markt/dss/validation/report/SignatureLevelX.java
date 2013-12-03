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

import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;

/**
 * Validation information for level X (CAdES, XAdES).
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureLevelX extends SignatureLevel {
    @XmlElement
    private TimestampVerificationResult[] signatureAndRefsTimestampsVerification;
    @XmlElement
    private TimestampVerificationResult[] referencesTimestampsVerification;

    public SignatureLevelX() {
        super();
    }

    public SignatureLevelX(AdvancedSignature signature, Result levelReached) {
        super(levelReached);
    }

    /**
     * The default constructor for SignatureLevelBES.
     * 
     * @param name
     * @param signature
     * @param levelReached
     */
    public SignatureLevelX(AdvancedSignature signature, Result levelReached, TimestampVerificationResult[] signatureAndRefsTimestampsVerification,
            TimestampVerificationResult[] referencesTimestampsVerification) {
        super(levelReached);
        this.signatureAndRefsTimestampsVerification = signatureAndRefsTimestampsVerification;
        this.referencesTimestampsVerification = referencesTimestampsVerification;
    }

    public SignatureLevelX(AdvancedSignature signature, Result levelReached,
            List<TimestampVerificationResult> signatureAndRefsTimestampsVerification,
            List<TimestampVerificationResult> referencesTimestampsVerification) {
        super(levelReached);
        TimestampVerificationResult[] array1 = new TimestampVerificationResult[signatureAndRefsTimestampsVerification.size()];

        this.signatureAndRefsTimestampsVerification = signatureAndRefsTimestampsVerification.toArray(array1);

        TimestampVerificationResult[] array2 = new TimestampVerificationResult[referencesTimestampsVerification.size()];
        this.referencesTimestampsVerification = referencesTimestampsVerification.toArray(array2);
    }

    /**
     * @return the signatureAndRefsTimestampsVerification
     */
    public TimestampVerificationResult[] getSignatureAndRefsTimestampsVerification() {
        return signatureAndRefsTimestampsVerification;
    }

    /**
     * @return the referencesTimestampsVerification
     */
    public TimestampVerificationResult[] getReferencesTimestampsVerification() {
        return referencesTimestampsVerification;
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

        res.append(indentStr).append("[Level X\r\n");
        indentStr += "\t";

        res.append(indentStr).append("LevelReached: ").append(status).append("\r\n");
        if (getSignatureAndRefsTimestampsVerification() != null) {
            for (TimestampVerificationResult stv : getSignatureAndRefsTimestampsVerification()) {
                res.append(indentStr).append("SignatureAndRefsTimestampsVerification:\r\n");
                res.append((stv == null) ? null : stv.toString(indentStr));
            }
        }
        if (getReferencesTimestampsVerification() != null) {
            for (TimestampVerificationResult stv : getReferencesTimestampsVerification()) {
                res.append(indentStr).append("ReferencesTimestampsVerification:\r\n");
                res.append((stv == null) ? null : stv.toString(indentStr));
            }
        }

        indentStr = indentStr.substring(1);
        res.append(indentStr).append("]\r\n");

        return res.toString();
    }

    @Override
    public String toString() {
        return toString("");
    }
}
