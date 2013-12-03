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

import eu.europa.ec.markt.dss.signature.SignatureParameters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;

/**
 * The usage of this interface permit the user to choose the underlying PDF library use to created PDF signatures.
 * 
 * 
 * @version $Revision: 1711 $ - $Date: 2013-03-04 18:22:32 +0100 (lun., 04 mars 2013) $
 */
public interface PDFSignatureService {

    /**
     * Return the digest value of a PDF document
     * 
     * @param pdfData
     * @param parameters
     * @return
     * @throws IOException
     */
    byte[] digest(InputStream pdfData, SignatureParameters parameters) throws IOException;

    /**
     * Sign a PDF document
     * 
     * @param pdfData
     * @param signatureValue
     * @param signedStream
     * @param parameters
     * @throws IOException
     */
    void sign(InputStream pdfData, byte[] signatureValue, OutputStream signedStream, SignatureParameters parameters)
            throws IOException;

    /**
     * Retrieve and trigger validation of the signatures from a PDF document
     * 
     * @param input
     * @param callback
     * @throws IOException
     * @throws SignatureException
     */
    void validateSignatures(InputStream input, SignatureValidationCallback callback) throws IOException,
            SignatureException;

}