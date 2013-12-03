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

import java.util.logging.Level;
import java.util.logging.Logger;

import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;

/**
 * Fetchs revocation data from a certificate by querying an OCSP server first and then a CRL server if no OCSP response
 * could be retrieved.
 *
 * @version $Revision: 1820 $ - $Date: 2013-03-28 15:55:47 +0100 (Thu, 28 Mar 2013) $
 */

public class OCSPAndCRLCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = Logger.getLogger(OCSPAndCRLCertificateVerifier.class.getName());

    private OCSPSource ocspSource;

    private CRLSource crlSource;

    private final CertificatePool validationCertPool;

    /**
     * Build a OCSPAndCRLCertificateVerifier that will use the provided CRLSource and OCSPSource
     *
     * @param crlSource
     * @param ocspSource
     * @param validationCertPool
     */
    public OCSPAndCRLCertificateVerifier(final CRLSource crlSource, final OCSPSource ocspSource, final CertificatePool validationCertPool) {

        this.crlSource = crlSource;
        this.ocspSource = ocspSource;
        this.validationCertPool = validationCertPool;
    }

    @Override
    public RevocationToken check(final CertificateToken token) {

        if (ocspSource != null) {

            final OCSPCertificateVerifier ocspVerifier = new OCSPCertificateVerifier(ocspSource, validationCertPool);
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("OCSP request for " + token.getDSSIdAsString());
            }
            final RevocationToken revocation = ocspVerifier.check(token);
            if (revocation != null && revocation.getStatus() != null) {

            /*
             * Valid or not, an OCSP response has been retrieved. One should look in the ValidationReport to see the
             * result.
             */
                if (LOG.isLoggable(Level.INFO)) {
                    LOG.fine("OCSP validation done, don't need for CRL");
                }
                return revocation;
            }
        }
        if (crlSource != null) {

            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("No OCSP check performed, looking for a CRL for " + token.getDSSIdAsString());
            }
            /**
             * The validationPool is not needed for the CRLCertificateVerifier because it should be signed by the same certificate as the
             * certificate to be checked.
             */
            final CRLCertificateVerifier crlVerifier = new CRLCertificateVerifier(crlSource);
            final RevocationToken revocation = crlVerifier.check(token);
            if (revocation != null && revocation.getStatus() != null) {

                if (LOG.isLoggable(Level.INFO)) {
                    LOG.info("CRL check has been performed. Valid or not, the verification is done");
                }
                return revocation;
            }
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("We have no response from OCSP nor CRL");
            }
        }
        return null;
    }
}
