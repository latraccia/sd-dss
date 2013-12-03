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

package eu.europa.ec.markt.dss.applet.service;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerResponseMessage;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * Return all the matching X509Certificate according to the X500Principal
 *
 * @version $Revision: 2910 $ - $Date: 2013-11-08 15:18:08 +0100 (ven., 08 nov. 2013) $
 */

public class PotentialIssuersRequestHandler extends AbstractServiceHandler<PotentialIssuerRequestMessage, PotentialIssuerResponseMessage> {

    private static final Logger LOG = Logger.getLogger(PotentialIssuersRequestHandler.class.getName());
    private eu.europa.ec.markt.dss.validation102853.CertificateSource certificateSource;

    /**
     * @param certificateSource the certificateSource to set
     */
    public void setCertificateSource(eu.europa.ec.markt.dss.validation102853.CertificateSource certificateSource) {
        this.certificateSource = certificateSource;
    }

    @Override
    protected PotentialIssuerResponseMessage handleRequest(final PotentialIssuerRequestMessage message) throws IOException {

        try {

            final X500Principal x500Principal = new X500Principal(message.getIssuerPrincipal());
            System.out.println("NEW_CERT REQUEST: " + x500Principal.getName(X500Principal.CANONICAL));// !!!
            final PotentialIssuerResponseMessage response = new PotentialIssuerResponseMessage();

            final CertificatePool certificatePool = certificateSource.getCertificatePool();
            final List<CertificateToken> certificateTokens = certificatePool.get(x500Principal);

            final int count = certificateTokens.size();
            System.out.println("NEW_CERT REQUEST: CERTIFICATE(S) FOUND=" + count);// !!!

            final byte[][] potentialIssuerArray = new byte[count][];
            final String[][] sourceArray = new String[count][];
            final Serializable[][] serviceInfoArray = new Serializable[count][];

            for (int ii = 0; ii < count; ii++) {

                final CertificateToken certificateToken = certificateTokens.get(ii);
                potentialIssuerArray[ii] = certificateToken.getCertificate().getEncoded();

                final List<CertificateSourceType> sourceList = certificateToken.getSource();
                sourceArray[ii] = new String[sourceList.size()];
                int jj = 0;
                for (final CertificateSourceType sourceType : sourceList) {
                    System.out.println("\t--> " + sourceType.name());
                    sourceArray[ii][jj++] = sourceType.name();
                }

                List<ServiceInfo> serviceInfoList = certificateToken.getAssociatedTSPS();
                serviceInfoArray[ii] = new ServiceInfo[serviceInfoList.size()];
                int kk = 0;
                for (final ServiceInfo serviceInfo : serviceInfoList) {
                    System.out.println("\t--> " + serviceInfo.getStatus());
                    serviceInfoArray[ii][kk] = serviceInfo;
                }
                serviceInfoArray[ii][kk++] = certificateToken.getAssociatedTSPS().get(0);
            }

            response.setPotentialIssuer(potentialIssuerArray);
            response.setSource(sourceArray);
            response.setServiceInfo(serviceInfoArray);
            System.out.println("NEW_CERT REQUEST: RESPONSE SENT");// !!!
            System.out.println("");
            return response;
        } catch (CertificateException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, ex);
        }
    }
}
