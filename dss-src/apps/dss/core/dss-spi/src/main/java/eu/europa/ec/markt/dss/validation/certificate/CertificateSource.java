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

package eu.europa.ec.markt.dss.validation.certificate;

import java.io.IOException;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * The validation of a certificate requires to access some other certificates from multiple sources (Trusted List, Trust
 * Store, the signature itself). This interface provides an abstraction for accessing a certificate, regardless of the
 * source.
 * 
 * 
 * @version $Revision: 1858 $ - $Date: 2013-04-08 09:53:08 +0200 (lun., 08 avr. 2013) $
 */

public interface CertificateSource {

    /**
     * Give all certificates corresponding to a subject name. Regardless of other criteria, like validity.
     * 
     * @param subjectName
     * @return A list of certificates (and their respective context) corresponding to the subjectName. Never returns
     *         null.
     * @throws IOException
     */
	// TODO (BOB): An audit of all classes that use this interface must be made to see if an empty list is returned in case of an unsuccessful search.
    List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) throws IOException;

}
