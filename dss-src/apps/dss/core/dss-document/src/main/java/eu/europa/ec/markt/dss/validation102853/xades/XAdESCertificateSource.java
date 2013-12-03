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

package eu.europa.ec.markt.dss.validation102853.xades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.SignatureCertificateSource;

/**
 * Retrieve Certificates contained in a XAdES structure
 *
 * @version $Revision: 1758 $ - $Date: 2013-03-14 20:35:36 +0100 (Thu, 14 Mar 2013) $
 */

public class XAdESCertificateSource extends SignatureCertificateSource {

    private static final Logger LOG = Logger.getLogger(XAdESCertificateSource.class.getName());

    private final Element signatureElement;

    private List<CertificateToken> keyInfoCerts;

    private List<CertificateToken> encapsulatedCerts;

    /**
     * The default constructor for XAdESCertificateSource. All certificates are extracted during instantiation.
     *
     * @param signatureElement
     * @param certPool
     */
    public XAdESCertificateSource(final Element signatureElement, final CertificatePool certPool) {

        super(certPool);
        if (signatureElement == null) {

            throw new DSSException("signatureElement is null, it must be provided!");
        }
        this.signatureElement = signatureElement;
        extract();
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("+XAdESCertificateSource");
        }
    }

    /**
     * This method extracts all encapsulated certificates from the signature and adds them to validationCertPool.
     *
     * @throws DSSException
     */
    @Override
    protected void extract() throws DSSException {

        if (certificateTokens == null) {

            certificateTokens = new ArrayList<CertificateToken>();
            encapsulatedCerts = getCerts(XAdESSignature.XPATH_ENCAPSULATED_X509_CERTIFICATE);
            keyInfoCerts = getCerts(XAdESSignature.XPATH_KEY_INFO_X509_CERTIFICATE);
        }
    }

    /**
     * @param node
     * @return
     */
    private List<CertificateToken> getCerts(final String node) {

        final List<CertificateToken> list = new ArrayList<CertificateToken>();
        final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, node);
        for (int ii = 0; ii < nodeList.getLength(); ii++) {

            final Element certEl = (Element) nodeList.item(ii);
            final byte[] derEncoded = DSSUtils.base64Decode(certEl.getTextContent());
            final X509Certificate cert = DSSUtils.loadCertificate(derEncoded);
            final CertificateToken certToken = addCertificate(cert);
            list.add(certToken);
        }
        return list;
    }

    /**
     * Returns the list of certificates included in
     * ".../xades:UnsignedSignatureProperties/xades:CertificateValues/xades:EncapsulatedX509Certificate" node
     *
     * @return list of X509Certificate(s)
     */
    public List<CertificateToken> getEncapsulatedCertificates() throws DSSException {

        return encapsulatedCerts;
    }

    /**
     * Returns the list of certificates included in "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node
     *
     * @return list of X509Certificate(s)
     */
    public List<CertificateToken> getKeyInfoCertificates() throws DSSException {

        return keyInfoCerts;
    }
}
