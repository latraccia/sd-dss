/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853.pades;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;

/**
 * Validation of PDF document.
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class PDFDocumentValidator extends SignedDocumentValidator {

    // private static final Logger LOG = Logger.getLogger(PDFDocumentValidator.class.getName());

    final PDFSignatureService pdfSignatureService;

    /**
     * The default constructor for PDFDocumentValidator.
     */
    public PDFDocumentValidator(final DSSDocument document) {

        this.document = document;
        pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
    }

    @Override
    public List<AdvancedSignature> getSignatures() {

        final List<AdvancedSignature> list = new ArrayList<AdvancedSignature>();
        try {
            pdfSignatureService.validateSignatures(document.openStream(), new SignatureValidationCallback() {

                @Override
                public void validate(PdfDict catalog, PdfDict outerCatalog, X509Certificate signingCert, Date signingTime,
                                     Certificate[] chain, PdfDict signatureDictionary, PdfSignatureInfo pk) {

                    if (signingCert == null) {
                        throw new NotETSICompliantException(MSG.NO_SIGNING_CERTIFICATE);
                    }

                    if (signingTime == null) {
                        // throw new NotETSICompliantException(MSG.NO_SIGNING_TIME);
                    }

                    try {
                        if (signatureDictionary != null && !signatureDictionary.hasANameWithValue("Type", "DocTimeStamp")) {

                            list.add(new PAdESSignature(document, catalog, outerCatalog, signatureDictionary, pk, validationCertPool));
                        }
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                }
            });
        } catch (SignatureException e) {

            throw new RuntimeException(e);
        } catch (IOException e) {

            throw new RuntimeException(e);
        }
        return list;
    }
}
