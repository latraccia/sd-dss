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

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.TrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * @version $Revision: 2411 $ - $Date: 2013-08-26 07:01:25 +0200 (Mon, 26 Aug 2013) $
 */

public class RemoteCertificateSource implements CertificateSource {

    private static final Logger LOG = Logger.getLogger(RemoteCertificateSource.class.getName());

    private TrustedCertificateSource certificateSource;

    public RemoteCertificateSource() {
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * eu.europa.ec.markt.dss.validation.certificate.CertificateSource#getCertificateBySubjectName(javax.security.auth
     * .x500.X500Principal)
     */
    @Override
    public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {

        final List<CertificateAndContext> list = new ArrayList<CertificateAndContext>();

        final List<CertificateToken> certTokens = certificateSource.get(subjectName);
        for (final CertificateToken certToken : certTokens) {

            CertificateAndContext certAndContext = new CertificateAndContext();
            certAndContext.setCertificate(certToken.getCertificate());
            certAndContext.setCertificateSource(CertificateSourceType.TRUSTED_LIST);
            List<ServiceInfo> serviceInfoList = certToken.getAssociatedTSPS();
            if (serviceInfoList.size() > 0) {

                ServiceInfo serviceInfo = serviceInfoList.get(0);
                eu.europa.ec.markt.dss.validation.tsl.ServiceInfo si = new eu.europa.ec.markt.dss.validation.tsl.ServiceInfo();
                si.setTspName(serviceInfo.getTspName());
                si.setTspTradeName(serviceInfo.getTspTradeName());
                si.setServiceName(serviceInfo.getServiceName());
                si.setTspPostalAddress(serviceInfo.getTspPostalAddress());
                si.setTspElectronicAddress(serviceInfo.getTspElectronicAddress());
                si.setType(serviceInfo.getType());
                si.setCurrentStatus(serviceInfo.getStatus());
                si.setCurrentStatusStartingDate(serviceInfo.getStatusStartDate());
                si.setStatusEndingDateAtReferenceTime(serviceInfo.getStatusEndDate());
                si.setTlWellSigned(serviceInfo.isTlWellSigned());
                certAndContext.setContext(si);
            }
            list.add(certAndContext);
        }
        return list;
    }

    public void setDelegate(TrustedCertificateSource certificateSource) {

        this.certificateSource = certificateSource;
    }
}
