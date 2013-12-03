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

package eu.europa.ec.markt.dss.validation;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Implements a check that can be executed for a certificate.
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public interface CertificateStatusVerifier {

    /***
     * Check the validity of the certificate at the validationDate. The operation return a CertificateStatus if the
     * check could be executed. The result of the validation is contained in the object. This mean by example that if
     * there is some OCSP response saying that the certificate is invalid at the validation date, then the operation
     * return a CertificateStatus (a response has been found) but the status is invalid.
     * 
     * @param certificate The certificate to be verified
     * @param issuerCertificate This (potential) issuer of the certificate
     * @param validationDate The time for which the validation has to be done (maybe in the past)
     * @return A CertificateStatus if the check could be performed. (But still, the certificate can be REVOKED). Null
     *         otherwise.
     */
    CertificateStatus check(X509Certificate certificate, X509Certificate issuerCertificate, Date validationDate);

}