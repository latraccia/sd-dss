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

package eu.europa.ec.markt.dss.applet.io;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.RemoteCertificateSource;
import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerResponseMessage;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonTrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * CertificateSource that use the server backend for the operation execution.
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class RemoteAppletTSLCertificateSource extends CommonTrustedCertificateSource implements RemoteCertificateSource {

    /**
     * This object allows to communicate with the server. A request can be sent and un answer received. <code>PotentialIssuerRequestMessage</code>,
     * <code>PotentialIssuerResponseMessage</code> are used.
     */
    private RemoteCertificateService remoteCertificateService = new RemoteCertificateService();

    /**
     * Define the URL of the service providing certificates
     *
     * @param serviceUrl the serviceUrl to set
     */
    @Override
    public void setServiceUrl(String serviceUrl) {

        remoteCertificateService.setUrl(serviceUrl);
    }

    /**
     * @param dataLoader the dataLoader to set
     */
    @Override
    public void setDataLoader(HTTPDataLoader dataLoader) {

        remoteCertificateService.setDataLoader(dataLoader);
    }

    /**
     * This method is not applicable for this kind of certificates source.
     *
     * @param certificate the certificate you have to trust
     * @return
     */
    @Override
    public CertificateToken addCertificate(final X509Certificate certificate) {

        throw new DSSException("This method is not applicable for this kind of certificates source.");
    }

    @Override
    public List<CertificateToken> get(final X500Principal x500Principal) {

        try {

            final PotentialIssuerRequestMessage request = new PotentialIssuerRequestMessage();
            request.setIssuerPrincipal(x500Principal.getEncoded());

            final PotentialIssuerResponseMessage response = remoteCertificateService.sendAndReceive(request);

            final List<CertificateToken> certificateTokens = new ArrayList<CertificateToken>();
            if (response.getPotentialIssuer() != null) {

                for (int ii = 0; ii < response.getPotentialIssuer().length; ii++) {

                    final List<CertificateSourceType> sourceTypeList = getSourceTypeList(response.getSource()[ii]);
                    final List<ServiceInfo> serviceInfoList = getServiceInfoList(response.getServiceInfo()[ii]);

                    final byte[] certificateBytes = response.getPotentialIssuer()[ii];
                    final X509Certificate certificate = DSSUtils.loadCertificate(certificateBytes);

                    final CertificateToken certificateToken = addCertificate(certificate, sourceTypeList, serviceInfoList);
                    certificateTokens.add(certificateToken);
                }
            }
            return certificateTokens;
        } catch (IOException e) {

            throw new DSSException(e);
        }
    }

    private List<ServiceInfo> getServiceInfoList(final Serializable[] serviceInfoArray) {

        final List<ServiceInfo> serviceInfoList = new ArrayList<ServiceInfo>();
        for (int jj = 0; jj < serviceInfoArray.length; jj++) {

            final ServiceInfo serviceInfo = (ServiceInfo) serviceInfoArray[jj];
            serviceInfoList.add(serviceInfo);
        }
        return serviceInfoList;
    }

    private List<CertificateSourceType> getSourceTypeList(final String[] sourceArray) {

        final List<CertificateSourceType> sourceList = new ArrayList<CertificateSourceType>();
        for (int jj = 0; jj < sourceArray.length; jj++) {

            final CertificateSourceType certificateSource = CertificateSourceType.valueOf(sourceArray[jj]);
            sourceList.add(certificateSource);
        }
        return sourceList;
    }
}
