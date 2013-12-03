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

package eu.europa.ec.markt.dss.signature.pdf;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * 
 * Callback used by the PDFSignatureService to validate a specific PDF signature. 
 * 
 * @version $Revision: 1711 $ - $Date: 2013-03-04 18:22:32 +0100 (lun., 04 mars 2013) $
 */
public interface SignatureValidationCallback {

    /**
     * Validate the signature
     * 
     * @param reader the PdfReader corresponding to the revision of the document which was signed
     * @param outerCatalog the catalog of the "outer" document on which the signature was put on, containing parts non
     *            covered by the signature. This is helpful for instance to retrieve the DSS dictionary of a PAdES-LTV
     *            signature.
     * @param signingCert
     * @param signingDate
     * @param certs
     * @param signatureDictionary the signature dictionary. Retrieve the signature contents as a byte array like this:
     *            <code>byte[] signatureBlock = signatureDictionary.get(PdfName.CONTENTS)).getBytes()</code>
     * @param pk
     */
    void validate(PdfDict catalog, PdfDict outerCatalog, X509Certificate signingCert, Date signingDate,
            Certificate[] certs, PdfDict signatureDictionary, PdfSignatureInfo pk);

}
