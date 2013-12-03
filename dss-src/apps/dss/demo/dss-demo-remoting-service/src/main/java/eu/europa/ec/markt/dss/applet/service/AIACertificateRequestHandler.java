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

import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.applet.shared.CertificateFromAIARequestMessage;
import eu.europa.ec.markt.dss.applet.shared.CertificateFromAIAResponseMessage;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Return all the matching X509Certificate according to the X500Principal
 * 
 *
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class AIACertificateRequestHandler extends
        AbstractServiceHandler<CertificateFromAIARequestMessage, CertificateFromAIAResponseMessage> {

    private static final Logger LOG = Logger.getLogger(AIACertificateRequestHandler.class.getName());

    private CertificateSourceFactory aiaCertificateSourceFactory;

    /**
     * @param aiaCertificateSourceFactory the aiaCertificateSourceFactory to set
     */
    public void setAiaCertificateSourceFactory(CertificateSourceFactory aiaCertificateSourceFactory) {
        this.aiaCertificateSourceFactory = aiaCertificateSourceFactory;
    }

    @Override
    protected CertificateFromAIAResponseMessage handleRequest(CertificateFromAIARequestMessage message)
            throws IOException {

        X509Certificate cert = null;

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(message.getCertificate()));
        } catch (CertificateException ex) {
            throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
        }

        CertificateSource source = aiaCertificateSourceFactory.createAIACertificateSource(cert);
        List<CertificateAndContext> certs = source.getCertificateBySubjectName(cert.getIssuerX500Principal());

        try {
            
            CertificateFromAIAResponseMessage response = new CertificateFromAIAResponseMessage();
            
            if (certs.size() > 0) {
                response.setCertificate(certs.get(0).getCertificate().getEncoded());
            }
            return response;
            
        } catch (CertificateException ex) {
            // Should never happens
            LOG.log(Level.SEVERE, null, ex);
            throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
        }

    }

}
