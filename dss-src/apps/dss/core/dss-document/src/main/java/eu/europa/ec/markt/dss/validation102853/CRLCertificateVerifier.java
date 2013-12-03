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

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.crl.OnlineCRLSource;

/**
 * Verifier based on CRL
 *
 * @version $Revision: 1757 $ - $Date: 2013-03-14 20:33:28 +0100 (Thu, 14 Mar 2013) $
 */

public class CRLCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = Logger.getLogger(CRLCertificateVerifier.class.getName());

    private final CRLSource crlSource;

    /**
     * Main constructor.
     *
     * @param crlSource the CRL repository used by this CRL trust linker.
     */
    public CRLCertificateVerifier(final CRLSource crlSource) {

        this.crlSource = crlSource;
    }

    @Override
    public RevocationToken check(final CertificateToken toCheckToken) {

        String crlUri = null;
        try {

            if (crlSource == null) {

                toCheckToken.extraInfo().infoCRLSourceIsNull();
                return null;
            }
            final X509Certificate toCheckCert = toCheckToken.getCertificate();
            final X509Certificate issuerCert = toCheckToken.getIssuerToken().getCertificate();
            final X509CRL x509crl = crlSource.findCrl(toCheckCert, issuerCert);
            if (crlSource instanceof OnlineCRLSource) {

                crlUri = ((OnlineCRLSource) crlSource).getCrlUri(toCheckCert);
            }
            if (x509crl == null) {

                if (LOG.isLoggable(Level.INFO)) {
                    LOG.info("No CRL found for " + toCheckToken.getDSSIdAsString());
                }
                if (crlSource instanceof OnlineCRLSource) {

                    toCheckToken.extraInfo().infoNoCRLInfoFound(crlUri);
                }
                return null;
            }
            final CRLToken crlToken = new CRLToken(x509crl);
            if (crlSource instanceof OnlineCRLSource) {

                crlToken.setSourceURI(crlUri);
            }
            if (!isCRLTokenValid(crlToken, toCheckToken.getIssuerToken())) {

                LOG.warning("The CRL is not valid !");
                toCheckToken.extraInfo().infoCRLIsNotValid();
                return null;
            }
            final X509CRLEntry crlEntry = x509crl.getRevokedCertificate(toCheckCert.getSerialNumber());
            if (null == crlEntry) {

                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("CRL OK for: " + toCheckToken.getDSSIdAsString());
                }
            /*
             * If there is no entry in the CRL, the certificate is more likely to be valid
             */
                crlToken.setStatus(true);
            } else {

                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("CRL reports certificate: " + toCheckToken.getDSSIdAsString() + " as revoked since " + crlEntry.getRevocationDate());
                }
                crlToken.setStatus(false);
                crlToken.setRevocationDate(crlEntry.getRevocationDate());
                final byte[] extensionBytes = crlEntry.getExtensionValue(X509Extension.reasonCode.getId());
                ASN1InputStream dIn = null;
                try {

                    dIn = new ASN1InputStream(extensionBytes);
                    CRLReason reason = new CRLReason(DEREnumerated.getInstance(dIn.readObject()));
                    crlToken.setReason(reason.toString());
                } catch (IllegalArgumentException e) {
                    // In the test case XAdESTest003 testTRevoked() there is an error in the revocation reason.
                    LOG.warning("Error when revocation reason decoding from CRL: " + e.toString());
                    crlToken.setReason(new CRLReason(7).toString()); // unknown
                } finally {

                    DSSUtils.closeQuietly(dIn);
                }
            }
            toCheckToken.setRevocationToken(crlToken);
            return crlToken;
        } catch (final Exception e) {

            LOG.log(Level.SEVERE, "Exception when accessing CRL for " + toCheckToken.getDSSIdAsString(), e);
            toCheckToken.extraInfo().infoCRLException(crlUri, e);
            return null;
        }
    }

    /**
     * Checks:<br>
     * - if the issuer of the CRL is present,<br>
     * - the signature of the CRL,<br>
     * - the age of data,<br>
     * - if the KeyUsage extension for CRL issuing certificate is resent,<br>
     * - if the CRLSign bit is set for CRL issuing certificate
     *
     * @param crlToken    cannot be null
     * @param issuerToken supposed issuer's signing certificate
     * @return
     */
    private boolean isCRLTokenValid(final CRLToken crlToken, final CertificateToken issuerToken) {

        if (issuerToken == null) {

            throw new DSSNullException(CertificateToken.class, "issuerToken");
        }
        /**
         *  The CRL and the certificate is being checked must have the same issuer.
         */
        if (!crlToken.isSignedBy(issuerToken)) {

            crlToken.infoNotValidSignature();
            return false;
        }
        // assert CRLSign KeyUsage bit
        final boolean[] keyUsage = issuerToken.getCertificate().getKeyUsage();
        if (keyUsage == null || (keyUsage != null && !keyUsage[6])) {

            crlToken.infoNoKeyUsageExtension();
            return false;
        }
        return true;
    }
}
