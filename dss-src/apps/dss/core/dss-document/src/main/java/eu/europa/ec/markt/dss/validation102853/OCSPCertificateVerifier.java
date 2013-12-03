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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation.ocsp.OnlineOCSPSource;

/**
 * Check the status of the certificate using an OCSPSource
 *
 * @version $Revision: 1757 $ - $Date: 2013-03-14 20:33:28 +0100 (Thu, 14 Mar 2013) $
 */

public class OCSPCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = Logger.getLogger(OCSPCertificateVerifier.class.getName());

    private final OCSPSource ocspSource;

    private final CertificatePool validationCertPool;

    /**
     * Create a CertificateVerifier that will use the OCSP Source for checking revocation data. The default constructor
     * for OCSPCertificateVerifier.
     *
     * @param ocspSource
     * @param validationCertPool
     */
    public OCSPCertificateVerifier(final OCSPSource ocspSource, final CertificatePool validationCertPool) {

        this.ocspSource = ocspSource;
        this.validationCertPool = validationCertPool;
    }

    @Override
    public RevocationToken check(final CertificateToken toCheckToken) {

        if (ocspSource == null) {

            LOG.warning("OCSPSource null");
            toCheckToken.extraInfo().infoOCSPSourceIsNull();
            return null;
        }
        try {

            final X509Certificate issuerCert = toCheckToken.getIssuerToken().getCertificate();
            final X509Certificate toCheckCert = toCheckToken.getCertificate();
            final BasicOCSPResp basicOCSPResp = ocspSource.getOCSPResponse(toCheckCert, issuerCert);
            if (basicOCSPResp == null) {

                if (LOG.isLoggable(Level.INFO)) {
                    LOG.info("OCSP response not found for " + toCheckToken.getDSSIdAsString());
                }
                if (ocspSource instanceof OnlineOCSPSource) {

                    final String uri = ((OnlineOCSPSource) ocspSource).getOCSPUri(toCheckCert);
                    toCheckToken.extraInfo().infoNoOCSPResponse(uri);
                }
                return null;
            }
            final CertificateID certificateId = new CertificateID(CertificateID.HASH_SHA1, issuerCert, toCheckCert.getSerialNumber());
            final SingleResp[] singleResps = basicOCSPResp.getResponses();
            for (final SingleResp singleResp : singleResps) {

                final CertificateID respCertId = singleResp.getCertID();
                if (!certificateId.equals(respCertId)) {

                    continue;
                }
                if (LOG.isLoggable(Level.FINE)) {

                    LOG.fine("OCSP thisUpdate: " + singleResp.getThisUpdate());
                    LOG.fine("OCSP nextUpdate: " + singleResp.getNextUpdate());
                }
                final OCSPToken ocspToken = new OCSPToken(basicOCSPResp, validationCertPool);
                if (ocspSource instanceof OnlineOCSPSource) {

                    ocspToken.setSourceURI(((OnlineOCSPSource) ocspSource).getOCSPUri(toCheckCert));
                }

                ocspToken.setIssuingTime(basicOCSPResp.getProducedAt());
                toCheckToken.setRevocationToken(ocspToken);
                final Object certStatus = singleResp.getCertStatus();
                if (certStatus == null) {

                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info("OCSP OK for: " + toCheckToken.getDSSIdAsString());
                    }
                    ocspToken.setStatus(true);
                } else {

                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info("OCSP certificate status: " + certStatus.getClass().getName());
                    }
                    if (certStatus instanceof RevokedStatus) {

                        if (LOG.isLoggable(Level.INFO)) {
                            LOG.info("OCSP status revoked");
                        }
                        final RevokedStatus revokedStatus = (RevokedStatus) certStatus;
                        ocspToken.setStatus(false);
                        ocspToken.setRevocationDate(revokedStatus.getRevocationTime());
                        final int reasonId = revokedStatus.getRevocationReason();
                        final CRLReason crlReason = new CRLReason(reasonId);
                        ocspToken.setReason(crlReason.toString());
                    } else if (certStatus instanceof UnknownStatus) {

                        if (LOG.isLoggable(Level.INFO)) {
                            LOG.info("OCSP status unknown");
                        }
                        ocspToken.setReason("OCSP status: unknown");
                    }
                }
                return ocspToken;
            }
        } catch (IOException e) {

            LOG.log(Level.SEVERE, "OCSP exception: " + e.getMessage(), e);
            toCheckToken.extraInfo().infoOCSPException(e);
            return null;
        } catch (OCSPException e) {

            LOG.severe("OCSP exception: " + e.getMessage());
            toCheckToken.extraInfo().infoOCSPException(e);
            throw new RuntimeException(e);
        }
        if (LOG.isLoggable(Level.INFO)) {
            LOG.fine("No matching OCSP response entry");
        }
        toCheckToken.extraInfo().infoNoOCSPResponse(null);
        return null;
    }
}
