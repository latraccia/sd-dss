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

package eu.europa.ec.markt.dss.validation102853;

import java.util.List;
import java.util.Set;

import eu.europa.ec.markt.dss.exception.DSSException;

public interface ValidationContext {

    /**
     * This function sets the signing certificate to be validated.
     *
     * @param signingCert
     */
    public void setCertificateToValidate(CertificateToken signingCert);

    /**
     * Carries out the validation process in recursive manner for not yet checked tokens and for the specific signature.
     *
     * @throws DSSException
     */
    public abstract void validate() throws DSSException;

    /**
     * Returns a read only list of all certificates used in the process of the validation of the signature. This list
     * includes the certificate to check, certification chain certificates, OCSP response certificate...
     *
     * @return The list of CertificateToken(s)
     */
    public abstract Set<CertificateToken> getProcessedCertificates();

    /**
     * Returns a read only list of all revocations used in the process of the validation of the signature.
     *
     * @return The list of CertificateToken(s)
     */
    public abstract Set<RevocationToken> getProcessedRevocations();

    /**
     * Returns a read only list of all timestamps processed during the validation of the signature.
     *
     * @return The list of CertificateToken(s)
     */
    public abstract Set<TimestampToken> getProcessedTimestamps();

    /**
     * Returns the list of signature timestamps.
     *
     * @return
     */
    public abstract List<TimestampToken> getTimestampTokens();

    /**
     * Returns the list of SigAndRefs timestamps.
     *
     * @return
     */
    public abstract List<TimestampToken> getSigAndRefsTimestamps();

    /**
     * Returns the list of RefsOnly timestamps.
     *
     * @return
     */
    public abstract List<TimestampToken> getRefsOnlyTimestamps();

    /**
     * Returns the list of Archive timestamps.
     *
     * @return
     */
    public abstract List<TimestampToken> getArchiveTimestamps();
}