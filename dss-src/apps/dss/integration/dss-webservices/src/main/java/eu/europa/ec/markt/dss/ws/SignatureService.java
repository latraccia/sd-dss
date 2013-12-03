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

package eu.europa.ec.markt.dss.ws;

import java.io.IOException;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.ec.markt.dss.signature.SignatureFormat;

/**
 * Interface for the Contract of the Signature Web Service.
 * 
 *
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

@WebService
public interface SignatureService {

    /**
     * This web service operation digests a document according to a signature and signed properties.
     * 
     * @param document the document that shall be digested
     * @param signedPropertiesContainer the container for all SignedProperties
     * @param signatureInfo information about the kind of signature
     * @return a digest of the given document
     */
    @WebResult(name = "response")
    byte[] digestDocument(@WebParam(name = "document") final WSDocument document,
            @WebParam(name = "signedProperties") final SignedPropertiesContainer signedPropertiesContainer,
            @WebParam(name = "signatureInfo") final SignatureFormat signatureInfo) throws IOException;

    /**
     * This web service operation signs a document according to a previously signed digest, a level of signature, some
     * signature properties and keyinfo.
     * 
     * @param document the document that shall be signed
     * @param signedDigest the previously signed digest
     * @param signedPropertiesContainer the container for the matching SignedProperties
     * @param signatureInfoLevel the level of the signature
     * @return the signed document
     */
    @WebResult(name = "response")
    WSDocument signDocument(@WebParam(name = "document") final WSDocument document,
            @WebParam(name = "signedDigest") final byte[] signedDigest,
            @WebParam(name = "signedProperties") final SignedPropertiesContainer signedPropertiesContainer,
            @WebParam(name = "signatureInfoLevel") final SignatureFormat signatureInfoLevel) throws IOException;

    /**
     * This web service operation extends the signature of a given document to the level of the signature provided. The
     * document is only changed, if the given signature level is 'higher' than the signature level of the document.
     * 
     * @param signedDocument the signed document
     * @param signatureInfoLevel the level of the signature
     * @return the document with an extended signature
     */
    @WebResult(name = "response")
    WSDocument extendSignature(@WebParam(name = "signedDocument") final WSDocument signedDocument,
            @WebParam(name = "originalDocument") final WSDocument originalDocument,
            @WebParam(name = "signatureInfoLevel") final SignatureFormat signatureInfoLevel) throws IOException;

}