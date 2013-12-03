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

import java.util.logging.Logger;

import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;

/**
 * This class provides the different sources used to verify the status of a certificate using the Trusted List model. There are
 * four different types of sources to be defined:<br />
 * - Trusted certificates source;
 * - Adjunct certificates source (not trusted);
 * - OCSP source;
 * - CRL source.
 *
 * @version $Revision: 1754 $ - $Date: 2013-03-14 20:27:56 +0100 (Thu, 14 Mar 2013) $
 */

public class CommonCertificateVerifier implements CertificateVerifier {

    private static final Logger LOG = Logger.getLogger(CommonCertificateVerifier.class.getName());

    private TrustedCertificateSource trustedCertSource;

    private CertificateSource adjunctCertSource;

    private OCSPSource ocspSource;

    private CRLSource crlSource;

    private CertificateSource remoteTrustedCertSource;

    public CommonCertificateVerifier() {

        LOG.info("+ New CommonCertificateVerifier created.");
    }

    /**
     * @return
     */
    @Override
    public TrustedCertificateSource getTrustedCertSource() {

        return trustedCertSource;
    }

    /**
     * @return
     */
    @Override
    public OCSPSource getOcspSource() {

        return ocspSource;
    }

    /**
     * @return
     */
    @Override
    public CRLSource getCrlSource() {

        return crlSource;
    }

    /**
     * Defines the source of CRL used by this class
     *
     * @param crlSource the crlSource to set
     */
    @Override
    public void setCrlSource(CRLSource crlSource) {

        this.crlSource = crlSource;
    }

    /**
     * Defines the source of OCSP used by this class
     *
     * @param ocspSource the ocspSource to set
     */
    @Override
    public void setOcspSource(OCSPSource ocspSource) {

        this.ocspSource = ocspSource;
    }

    /**
     * Defines how the certificates from the Trusted Lists are retrieved. This source should provide trusted
     * certificates. These certificates are used as trusted anchors.
     *
     * @param trustedCertSource The source of trusted certificates.
     */
    @Override
    public void setTrustedCertSource(TrustedCertificateSource trustedCertSource) {

        this.trustedCertSource = trustedCertSource;
    }

    /**
     * @return
     */
    @Override
    public CertificateSource getAdjunctCertSource() {

        return adjunctCertSource;
    }

    /**
     * @param adjunctCertSource
     */
    @Override
    public void setAdjunctCertSource(CertificateSource adjunctCertSource) {

        this.adjunctCertSource = adjunctCertSource;
    }
}
