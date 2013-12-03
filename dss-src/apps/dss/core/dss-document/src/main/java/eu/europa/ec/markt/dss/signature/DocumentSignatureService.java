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

package eu.europa.ec.markt.dss.signature;

import java.io.IOException;
import java.io.InputStream;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * Interface for DocumentSignatureService. Provides operations for sign/verify a document.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */
public interface DocumentSignatureService {

   /**
    * Retrieves the stream of data that need to be signed.
    * 
    * @param document @param document - document to sign
    * @param parameters
    * @return
    * @throws DSSException
    */
   public InputStream toBeSigned(DSSDocument document, SignatureParameters parameters) throws DSSException;

   /**
    * Signs the document with the provided signatureValue.
    * 
    * @param document - document to sign
    * @param parameters
    * @param signatureValue
    * @return
    * @throws DSSException
    */
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters, byte[] signatureValue) throws DSSException;

   /**
    * 
    * Signs the document in the single operation
    * 
    * @param document
    * @param parameters
    * @return
    * @throws DSSException
    */
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters) throws DSSException;

   /**
    * Extends the level of the signatures in the document
    * 
    * @param document
    * @param parameters
    * @return
    * @throws DSSException
    */
   public DSSDocument extendDocument(DSSDocument document, SignatureParameters parameters) throws DSSException;

   /**
    * Extends the level of the signatures in the document
    * 
    * @param document
    * @param originalDocument In case of extending a detached signature up to level -A, the original document is needed.
    * @param parameters
    * @return
    * @throws IOException
    * @deprecated The originalDocument parameter is no longer necessary. If needed set
    *             {@link SignatureParameters#setOriginalDocument(DSSDocument)}
    */
   @Deprecated
   public DSSDocument extendDocument(DSSDocument document, DSSDocument originalDocument, SignatureParameters parameters) throws IOException;

   /**
    * @param Certificate verifier which is used when extending the signature.
    */
   public void setCertificateVerifier(CertificateVerifier certificateVerifier);

   /**
    * @param tspSource The time stamp source which is used when timestamping the signature.
    */
   public void setTspSource(TSPSource tspSource);
}