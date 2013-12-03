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

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * This class hosts the set of certificates which is used during the validation process. A certificate can be found in
 * different sources: trusted list, signature, OCSP response... but each certificate is unambiguously identified by its
 * issuer DN and serial number. This class allows to keep only one occurrence of the certificate regardless its
 * provenance. Two pool of certificates can be merged using the {@link #merge(CertificatePool)} method.
 *
 * @author bielecro
 */
public class CertificatePool implements Serializable {

    /**
     * Map of encapsulated certificates with unique DSS identifier as key (hash code calculated on issuer distinguished name and serial
     * number)
     */
    private Map<Integer, CertificateToken> certById = new HashMap<Integer, CertificateToken>();

    /**
     * Map f encapsulated certificates with subject distinguished name as key.
     */
    private Map<String, List<CertificateToken>> certBySubject = new HashMap<String, List<CertificateToken>>();

    /**
     * Returns the instance of a certificate token. If the certificate is not referenced yet a new instance of
     * {@link CertificateToken} is created.
     *
     * @param cert
     * @return
     */
    CertificateToken getInstance(final X509Certificate cert, final CertificateSourceType certSource) {

        return getInstance(cert, certSource, (ServiceInfo) null);
    }

    /**
     * This method returns the instance of a {@link CertificateToken} corresponding to the given {@link X509Certificate}.
     * If the given certificate is not yet present in the pool it will be added. If the {@link CertificateToken} exists
     * already in the pool but has no {@link ServiceInfo} this reference will be added.
     *
     * @param cert
     * @param certSource
     * @param serviceInfo
     * @return
     */
    CertificateToken getInstance(final X509Certificate cert, final CertificateSourceType certSource, final ServiceInfo serviceInfo) {

        final List<ServiceInfo> services = new ArrayList<ServiceInfo>();
        if (serviceInfo != null) {

            services.add(serviceInfo);
        }
        final List<CertificateSourceType> sources = new ArrayList<CertificateSourceType>();
        if (certSource != null) {

            sources.add(certSource);
        }
        return getInstance(cert, sources, services);
    }

    /**
     * This method returns the instance of a {@link CertificateToken} corresponding to the given {@link X509Certificate}.
     * If the given certificate is not yet present in the pool it will added. If the {@link CertificateToken} exists
     * already in the pool but has no {@link ServiceInfo} this reference will be added.
     *
     * @param cert
     * @param sources
     * @param services
     * @return
     */
    CertificateToken getInstance(final X509Certificate cert, final List<CertificateSourceType> sources, final List<ServiceInfo> services) {

        if (cert == null) {

            throw new RuntimeException("The certificate cannot be null.");
        }
        if (sources == null || sources.size() == 0) {

            throw new RuntimeException("The certificate source type must be set.");
        }

        final int id = CertificateIdentifier.getId(cert);
        CertificateToken certToken = certById.get(id);
        if (certToken == null) {

            certToken = CertificateToken.newInstance(cert, id);
            certById.put(id, certToken);
            final String subjectName = cert.getSubjectX500Principal().getName(X500Principal.CANONICAL);
            List<CertificateToken> list = certBySubject.get(subjectName);
            if (list == null) {

                list = new ArrayList<CertificateToken>();
                certBySubject.put(subjectName, list);
            }
            list.add(certToken);
        }
        for (final CertificateSourceType sourceType : sources) {

            certToken.addSourceType(sourceType);
        }
        if (services != null) {

            for (final ServiceInfo serviceInfo : services) {

                certToken.addServiceInfo(serviceInfo);
            }
        }
        return certToken;
    }

    /**
     * This method returns an unmodifiable list containing all encapsulated certificate tokens {@link CertificateToken}.
     *
     * @return
     */
    public List<CertificateToken> getCertificateTokens() {

        ArrayList<CertificateToken> certificateTokenArrayList = new ArrayList<CertificateToken>(certById.values());
        return Collections.unmodifiableList(certificateTokenArrayList);
    }

    /**
     * This method allows to add certificates from another {@link CertificatePool}. If an instance of the
     * {@link CertificateToken} already exists in this pool only the {@link ServiceInfo} and
     * {@link CertificateSourceType} are added.
     *
     * @param certPool
     */
    public void merge(final CertificatePool certPool) {

        Collection<CertificateToken> certTokens = certPool.certById.values();
        for (CertificateToken certificateToken : certTokens) {

            X509Certificate cert = certificateToken.getCertificate();
            List<CertificateSourceType> sources = certificateToken.getSource();
            List<ServiceInfo> services = certificateToken.getAssociatedTSPS();
            getInstance(cert, sources, services);
        }
    }

    /**
     * This method returns the list of certificates with the same issuerDN.
     *
     * @param x500Principal subject distinguished name to match.
     * @return If no match is found then an empty list is returned.
     */
    public List<CertificateToken> get(final X500Principal x500Principal) {

        List<CertificateToken> certificateTokenList = null;
        if (x500Principal != null) {

            final String x500PrincipalCanonicalized = x500Principal.getName(X500Principal.CANONICAL);
            certificateTokenList = certBySubject.get(x500PrincipalCanonicalized);
        }
        if (certificateTokenList == null) {

            certificateTokenList = new ArrayList<CertificateToken>();
        }
        return Collections.unmodifiableList(certificateTokenList);
    }
}
