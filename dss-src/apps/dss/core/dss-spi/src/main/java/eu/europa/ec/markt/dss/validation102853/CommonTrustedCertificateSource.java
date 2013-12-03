/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas BovÃ© 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * This class represents the simple list of trusted certificates.
 *
 * @version $Revision: 1845 $ - $Date: 2013-04-04 17:46:25 +0200 (Thu, 04 Apr 2013) $
 */

public class CommonTrustedCertificateSource extends CommonCertificateSource implements TrustedCertificateSource {

    @Override
    protected CertificateSourceType getCertificateSourceType() {

        return CertificateSourceType.TRUSTED_STORE;
    }

    protected CertificateToken addCertificate(final X509Certificate cert, final List<CertificateSourceType> sources,
                                              final List<ServiceInfo> services) {

        final CertificateToken certToken = certPool.getInstance(cert, sources, services);
        return certToken;
    }

    /**
     * This method allows to define (to add) any certificate as trusted. A service information is associated to this certificate. The
     * source of the certificate is set to <code>CertificateSourceType.TRUSTED_LIST</code>
     *
     * @param certificate the certificate you have to trust
     * @param serviceInfo the service information associated to the service
     * @return the corresponding certificate token
     */
    public CertificateToken addCertificate(final X509Certificate certificate, final ServiceInfo serviceInfo) {

        final CertificateToken certToken = certPool.getInstance(certificate, getCertificateSourceType(), serviceInfo);
        return certToken;
    }

    /**
     * This method allows to declare all certificates from a given key store as trusted.
     *
     * @param keyStore the set of certificates you have to trust
     */
    public void importAsTrusted(final KeyStoreCertificateSource keyStore) {

        final List<CertificateToken> certTokenList = keyStore.getCertificates();
        for (final CertificateToken certToken : certTokenList) {

            certPool.getInstance(certToken.getCertificate(), getCertificateSourceType());
        }
    }

    /**
     * Retrieves the list of all certificate tokens from this source.
     *
     * @return
     */
    public List<CertificateToken> getCertificates() {

        return certPool.getCertificateTokens();
        // throw new DSSException("This method method is not applicable for this kind of certificates source: CommonTrustedCertificateSource");
    }

    /**
     * This method return the <code>List</code> of <code>CertificateToken</code>(s) corresponding to the given subject distinguished name.
     * In the case of <code>CommonTrustedCertificateSource</code> the content of the encapsulated pool is equal to the content of the
     * source.
     *
     * @param x500Principal subject distinguished names of the certificate to find
     * @return If no match is found then an empty list is returned.
     */
    @Override
    public List<CertificateToken> get(final X500Principal x500Principal) {

        return certPool.get(x500Principal);
    }
}