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

package eu.europa.ec.markt.dss.applet.io;

import eu.europa.ec.markt.dss.applet.shared.OCSPRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.OCSPResponseMessage;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.ocsp.BasicOCSPResp;

/**
 * OCSPSource that use the server backend for the operation execution (proxy).
 * 
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class RemoteOCSPSource extends AbstractRemoteService<OCSPRequestMessage, OCSPResponseMessage> implements
        OCSPSource {

    @Override
    public BasicOCSPResp getOCSPResponse(X509Certificate certificate, X509Certificate issuerCertificate)
            throws IOException {

        try {
            OCSPRequestMessage request = new OCSPRequestMessage();
            request.setCertificate(certificate.getEncoded());
            request.setIssuerCert(issuerCertificate.getEncoded());

            OCSPResponseMessage response = sendAndReceive(request);

            if (response.getOcspResponse() == null) {
                return null;
            } else {
                ASN1InputStream input = new ASN1InputStream(response.getOcspResponse());
                ASN1Sequence sequence = (ASN1Sequence) input.readObject().toASN1Object();
                return new BasicOCSPResp(new BasicOCSPResponse(sequence));
            }
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

}
