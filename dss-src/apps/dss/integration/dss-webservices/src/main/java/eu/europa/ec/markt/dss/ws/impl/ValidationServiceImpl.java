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

package eu.europa.ec.markt.dss.ws.impl;

import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.report.ValidationReport;
import eu.europa.ec.markt.dss.ws.ValidationService;
import eu.europa.ec.markt.dss.ws.WSDocument;
import eu.europa.ec.markt.dss.ws.report.WSValidationReport;

import java.io.IOException;

import javax.jws.WebService;

/**
 * Implementation of the Interface for the Contract of the Validation Web Service.
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

@WebService(endpointInterface = "eu.europa.ec.markt.dss.ws.ValidationService", serviceName = "ValidationService")
public class ValidationServiceImpl implements ValidationService {

    private CertificateVerifier certificateVerifier;

    /**
     * @param certificateVerifier the certificateVerifier to set
     */
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public WSValidationReport validateDocument(WSDocument document, WSDocument originalContent) throws IOException {

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
        validator.setCertificateVerifier(certificateVerifier);
        validator.setExternalContent(originalContent);

        ValidationReport report = validator.validateDocument();
        return new WSValidationReport(report);
    }
}