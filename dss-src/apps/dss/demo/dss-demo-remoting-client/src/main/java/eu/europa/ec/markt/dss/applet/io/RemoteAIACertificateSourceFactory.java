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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.applet.shared.CertificateFromAIARequestMessage;
import eu.europa.ec.markt.dss.applet.shared.CertificateFromAIAResponseMessage;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceFactory;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

/**
 * CertificateSourceFactory that use the server backend for the operation execution.
 * 
 *
 * @version $Revision: 1945 $ - $Date: 2013-05-08 10:16:54 +0200 (mer., 08 mai 2013) $
 */

public class RemoteAIACertificateSourceFactory implements CertificateSourceFactory {

    private String serviceUrl;

    private HTTPDataLoader httpDataLoader;

    /**
     * @param serviceUrl the serviceUrl to set
     */
    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    /**
     * @param httpDataLoader the httpDataLoader to set
     */
    public void setHttpDataLoader(HTTPDataLoader httpDataLoader) {
        this.httpDataLoader = httpDataLoader;
    }

    @Override
    public CertificateSource createAIACertificateSource(X509Certificate certificate) {
        RemoteAIACertificateSource source = new RemoteAIACertificateSource(certificate);
        source.setUrl(serviceUrl + "/aia");
        source.setDataLoader(httpDataLoader);
        return source;
    }

    private static class RemoteAIACertificateSource extends
            AbstractRemoteService<CertificateFromAIARequestMessage, CertificateFromAIAResponseMessage> implements
            CertificateSource {

        private X509Certificate certificate;

        private CertificateFromAIAResponseMessage response = null;

        /**
         * The default constructor for RemoteAIACertificateSourceFactory.RemoteAIACertificateSource.
         */
        public RemoteAIACertificateSource(X509Certificate certificate) {
            this.certificate = certificate;
        }

        @Override
        public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {
            List<CertificateAndContext> list = new ArrayList<CertificateAndContext>();

            try {

                if (response == null) {
                    CertificateFromAIARequestMessage request = new CertificateFromAIARequestMessage();
                    request.setCertificate(certificate.getEncoded());
                    response = sendAndReceive(request);
                }

                if (response.getCertificate() != null) {
                    CertificateFactory factory = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(
                            response.getCertificate()));

                    if (cert.getSubjectX500Principal().equals(subjectName)) {
                        list.add(new CertificateAndContext());
                    }

                }
            } catch (CertificateEncodingException e) {
                
            	throw new RuntimeException(e);
            } catch (CertificateException e) {

            	throw new RuntimeException(e);
            } catch (IOException e) {

                throw new RuntimeException(e);
			}

            return list;
        }
    }

}
