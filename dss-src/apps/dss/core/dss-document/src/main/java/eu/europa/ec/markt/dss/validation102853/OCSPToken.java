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

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;

/**
 * OCSP Signed Token
 *
 * @version $Revision: 1824 $ - $Date: 2013-03-28 15:57:23 +0100 (Thu, 28 Mar 2013) $
 */

public class OCSPToken extends RevocationToken {

    private static final Logger LOG = Logger.getLogger(OCSPToken.class.getName());

    private final BasicOCSPResp ocspResp;

    private String sourceURI;

    /**
     * The default constructor for OCSPToken.
     *
     * @param ocspResp
     * @param validationCertPool
     */
    public OCSPToken(final BasicOCSPResp ocspResp, final CertificatePool validationCertPool) {

        if (ocspResp == null) {

            throw new RuntimeException("BasicOCSPResp cannot be null!");
        }
        this.ocspResp = ocspResp;
        this.extraInfo = new TokenValidationExtraInfo();
        try {

            for (final X509Certificate cert : ocspResp.getCerts(null)) {

                final CertificateToken certToken = validationCertPool.getInstance(cert, CertificateSourceType.OCSP_RESPONSE);
                if (isSignedBy(certToken)) {

                    break;
                }
            }
        } catch (NoSuchProviderException e) {
            throw new DSSException(e);
        } catch (OCSPException e) {
            throw new EncodingException(MSG.OCSP_CANNOT_BE_READ, e);
        }
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("OCSP token, produced at '" + DSSUtils.formatInternal(ocspResp.getProducedAt()) + "' added.");
        }
    }

    /**
     * @return the ocspResp
     */
    public BasicOCSPResp getOcspResp() {

        return ocspResp;
    }

    @Override
    public boolean isSignedBy(final CertificateToken issuerToken) {

        if (this.issuerToken != null) {

            return this.issuerToken.equals(issuerToken);
        }
        try {

            signatureInvalidityReason = "";
            signatureIntact = ocspResp.verify(issuerToken.getCertificate().getPublicKey(), "BC");
            if (signatureIntact) {

                this.issuerToken = issuerToken;
                algoUsedToSignToken = issuerToken.getSignatureAlgo();
                algoOIDUsedToSignToken = issuerToken.getSignatureAlgoOID();
                issuerX500Principal = issuerToken.getCertificate().getSubjectX500Principal();
            }
        } catch (NoSuchProviderException e) {
         /*
          * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for
          * this exception
          */
            throw new RuntimeException(e);
        } catch (OCSPException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
            signatureIntact = false;
        }
        return signatureIntact;
    }

    public String getSourceURI() {

        return sourceURI;
    }

    public void setSourceURI(final String sourceURI) {

        this.sourceURI = sourceURI;
    }

    @Override
    public int hashCode() {

        final int prime = 31;
        int result = 1;
        result = prime * result + ((ocspResp == null) ? 0 : ocspResp.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {

        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final OCSPToken other = (OCSPToken) obj;
        if (ocspResp == null) {
            if (other.ocspResp != null) {
                return false;
            }
        } else if (!ocspResp.equals(other.ocspResp)) {
            return false;
        }
        return true;
    }

    /**
     * This method returns the DSS abbreviation of the certificate. It is used for debugging purpose.
     *
     * @return
     */
    public String getAbbreviation() {

        return "OCSPToken[" + DSSUtils.formatInternal(ocspResp.getProducedAt()) + ", signedBy=" + issuerToken.getDSSIdAsString() + "]";
    }

    @Override
    public String toString(String indentStr) {

        StringBuffer out = new StringBuffer();
        out.append(indentStr).append("OCSPToken[");
        out.append(DSSUtils.formatInternal(ocspResp.getProducedAt()));
        out.append(", signedBy=").append(issuerToken.getDSSIdAsString()).append('\n');
        indentStr += "\t";
        out.append(indentStr).append("Signature algorithm: ").append(algoUsedToSignToken == null ? "?" : algoUsedToSignToken).append('\n');
        out.append(issuerToken.toString(indentStr)).append('\n');
        List<String> validationExtraInfo = extraInfo.getValidationInfo();
        if (validationExtraInfo.size() > 0) {

            for (String info : validationExtraInfo) {

                out.append('\n').append(indentStr).append("\t- ").append(info);
            }
            out.append('\n');
        }
        indentStr = indentStr.substring(1);
        out.append(indentStr).append("]");
        return out.toString();
    }
}
