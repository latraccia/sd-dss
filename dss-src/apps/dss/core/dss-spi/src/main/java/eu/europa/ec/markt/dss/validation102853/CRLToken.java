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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

public class CRLToken extends RevocationToken {

    private static final Logger LOG = Logger.getLogger(CRLToken.class.getName());

    private final X509CRL x509CRL;

    private String sourceURI;

    /**
     * The default constructor for CRLToken.
     *
     * @param x509crl
     */
    public CRLToken(final X509CRL x509crl) {

        if (x509crl == null) {

            throw new RuntimeException("X509CRL cannot be null!");
        }
        this.x509CRL = x509crl;
        this.algoUsedToSignToken = x509crl.getSigAlgName();
        this.algoOIDUsedToSignToken = x509crl.getSigAlgOID();

        this.issuingTime = x509crl.getThisUpdate();
        this.nextUpdate = x509crl.getNextUpdate();
        issuerX500Principal = x509crl.getIssuerX500Principal();
        this.extraInfo = new TokenValidationExtraInfo();
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("CRL token with this update date: '" + DSSUtils.formatInternal(x509crl.getThisUpdate()) + "' added.");
        }
    }

    /**
     * @return the x509crl
     */
    public X509CRL getX509crl() {

        return x509CRL;
    }

    @Override
    public boolean isSignedBy(final CertificateToken issuerToken) {

        if (this.issuerToken != null) {

            return this.issuerToken.equals(issuerToken);
        }
        signatureIntact = false;
        try {

            signatureInvalidityReason = "";
            x509CRL.verify(issuerToken.getCertificate().getPublicKey());
            signatureIntact = true;
            this.issuerToken = issuerToken;
        } catch (InvalidKeyException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        } catch (CRLException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        } catch (NoSuchAlgorithmException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        } catch (NoSuchProviderException e) {

         /*
          * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for
          * this exception
          */
            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
            throw new DSSException(e);
        } catch (SignatureException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        }
        return signatureIntact;
    }

    public String getSourceURI() {

        return sourceURI;
    }

    public void setSourceURI(final String sourceURI) {

        this.sourceURI = sourceURI;
    }

    /**
     *
     */
    public void infoNotValidSignature() {

        extraInfo.add("The CRL signature is not valid!");
    }

    /**
     *
     */
    public void infoNoKeyUsageExtension() {

        extraInfo.add("No KeyUsage extension for CRL issuing certificate!");
    }

    /**
     * This method returns the DSS abbreviation of the CRLToken. It is used for debugging purpose.
     *
     * @return
     */
    public String getAbbreviation() {

        return "CRLToken[" + (issuingTime == null ? "?" : DSSUtils
              .formatInternal(issuingTime)) + ", signedBy=" + (issuerToken == null ? "?" : issuerToken.getDSSIdAsString()) + "]";
    }

    @Override
    public String toString(String indentStr) {

        try {

            StringBuffer out = new StringBuffer();
            out.append(indentStr).append("CRLToken[\n");
            indentStr += "\t";
            out.append(indentStr).append("Version: ").append(x509CRL.getVersion()).append('\n');
            out.append(indentStr).append("Issuing time: ").append(issuingTime == null ? "?" : DSSUtils.formatInternal(issuingTime)).append('\n');
            out.append(indentStr).append("Signature algorithm: ").append(algoUsedToSignToken == null ? "?" : algoUsedToSignToken).append('\n');
            out.append(indentStr).append("Status: ").append(getStatus()).append('\n');
            if (issuerToken != null) {
                out.append(indentStr).append("Issuer's certificate: ").append(issuerToken.getDSSIdAsString()).append('\n');
            }
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
        } catch (Exception e) {

            return ((Object) this).toString();
        }
    }
}
