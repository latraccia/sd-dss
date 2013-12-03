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

package eu.europa.ec.markt.dss.validation.ocsp;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.BasicOCSPResp;

/**
 * The validation of a certificate may require the use of OCSP information. Theses information can be provided by multiple sources
 * (the signature itself, online OCSP server, ...). This interface provides an abstraction for a source of OCSPResp
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public interface OCSPSource {

	/**
	 * Gets an OCSPResp for the given certificate / issuer's certificate couple.
	 * 
	 * @param certificate The certificate for which the request is made
	 * @param issuerCertificate The issuer's certificate of the certificate
	 * @return An OCSPResp containing information about the validity of the certificate
	 */
	BasicOCSPResp getOCSPResponse(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException;

}
