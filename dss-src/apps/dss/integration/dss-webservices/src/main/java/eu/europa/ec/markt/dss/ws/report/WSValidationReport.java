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
import eu.europa.ec.markt.dss.validation.report.ValidationReport;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrap data of ValidationReport. Used to expose the information in the Webservice.
 * 
 * 
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSValidationReport {

    private WSTimeInformation _timeInformation;

    private List<WSSignatureInformation> _signatureInformationList;

    /**
     * The default constructor for WSValidationReport.
     */
    public WSValidationReport() {
    }

    /**
     * The default constructor for WSValidationReport.
     */
    public WSValidationReport(ValidationReport report) {
        this._timeInformation = new WSTimeInformation(report.timeInformation);
        _signatureInformationList = new ArrayList<WSSignatureInformation>();
        if (report.getSignatureInformationList() != null) {
            for (SignatureInformation info : report.getSignatureInformationList()) {
                _signatureInformationList.add(new WSSignatureInformation(info));
            }
        }
    }

    /**
     * @return the timeInformation
     */
    public WSTimeInformation getTimeInformation() {
        return _timeInformation;
    }

    /**
     * @param timeInformation the timeInformation to set
     */
    public void setTimeInformation(WSTimeInformation timeInformation) {
        this._timeInformation = timeInformation;
    }

    /**
     * @return the signatureInformationList
     */
    public List<WSSignatureInformation> getSignatureInformationList() {
        return _signatureInformationList;
    }

    /**
     * @param signatureInformationList the signatureInformationList to set
     */
    public void setSignatureInformationList(List<WSSignatureInformation> signatureInformationList) {
        this._signatureInformationList = signatureInformationList;
    }

}
