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

package eu.europa.ec.markt.dss.validation102853.toolbox;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.jce.provider.JDKDSAPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import sun.security.provider.DSAPublicKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

@SuppressWarnings("restriction")
public final class PublicKeyUtils {

    private static final Logger LOG = Logger.getLogger(SignedDocumentValidator.class.getName());

    private PublicKeyUtils() {
    }

    /**
     * This method returns the public algorithm extracted from public key infrastructure. (ex: RSA)
     *
     * @param publicKey
     * @return
     */
    public static String getPublicKeyEncryptionAlgo(final PublicKey publicKey) {

        String publicKeyAlgorithm = "?";
        // TODO: Bob (20130513) The list of different implementation need to be completed.
        if (publicKey instanceof RSAPublicKeyImpl) {

            final RSAPublicKeyImpl rsaPublicKey = (RSAPublicKeyImpl) publicKey;
            publicKeyAlgorithm = rsaPublicKey.getAlgorithm();
        } else if (publicKey instanceof JCERSAPublicKey) {

            final JCERSAPublicKey rsaPublicKey = (JCERSAPublicKey) publicKey;
            publicKeyAlgorithm = rsaPublicKey.getAlgorithm();
        } else if (publicKey instanceof JCEECPublicKey) {

            final JCEECPublicKey jceecPublicKey = (JCEECPublicKey) publicKey;
            publicKeyAlgorithm = jceecPublicKey.getAlgorithm();
        } else if (publicKey instanceof ECPublicKey) {

            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            publicKeyAlgorithm = ecPublicKey.getAlgorithm();
        } else if (publicKey instanceof DSAPublicKeyImpl) {

            DSAPublicKeyImpl dsaPublicKeyImpl = (DSAPublicKeyImpl) publicKey;
            publicKeyAlgorithm = dsaPublicKeyImpl.getAlgorithm();
        } else if (publicKey instanceof JDKDSAPublicKey) {

            JDKDSAPublicKey dsaPublicKeyImpl = (JDKDSAPublicKey) publicKey;
            publicKeyAlgorithm = dsaPublicKeyImpl.getAlgorithm();
        } else {

            LOG.warning("Unknown public key infrastructure: " + publicKey.getClass().getName());
        }
        if(!"?".equals(publicKeyAlgorithm)) {

            try {

            publicKeyAlgorithm = EncryptionAlgorithm.forName(publicKeyAlgorithm).getName();
            } catch (DSSException e) {

                LOG.severe(e.getMessage()) ;
            }
        }
        return publicKeyAlgorithm;
    }

    /**
     * This method returns the public key size extracted from public key infrastructure.
     *
     * @param publicKey
     * @return
     */
    public static int getPublicKeySize(final PublicKey publicKey) {

        int publicKeySize = -1;
        if (publicKey instanceof RSAPublicKeyImpl) {

            RSAPublicKeyImpl rsaPublicKey = (RSAPublicKeyImpl) publicKey;
            publicKeySize = rsaPublicKey.getModulus().bitLength();
        } else if (publicKey instanceof JCERSAPublicKey) {

            final JCERSAPublicKey rsaPublicKey = (JCERSAPublicKey) publicKey;
            publicKeySize = rsaPublicKey.getModulus().bitLength();
        } else if (publicKey instanceof JCEECPublicKey) {

            /**
             * The security of EC systems relies on the size of q, and the size of an EC key refers to the bit-length of
             * the subgroup size q.
             */
            final JCEECPublicKey jceecPublicKey = (JCEECPublicKey) publicKey;
            ECParameterSpec spec = jceecPublicKey.getParameters();
            if (spec != null) {

                publicKeySize = spec.getN().bitLength();
            } else {
                // We support the key, but we don't know the key length
                publicKeySize = 0;
                // publicKeySize = jceecPublicKey.getQ().getCurve().getFieldSize();
            }
        } else if (publicKey instanceof ECPublicKey) {

            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            java.security.spec.ECParameterSpec spec = ecPublicKey.getParams();
            if (spec != null) {

                // TODO: (Bob: 20130528) To be checked (need an example)
                publicKeySize = spec.getCurve().getField().getFieldSize();
            } else {

                publicKeySize = 0;
            }
        } else if (publicKey instanceof DSAPublicKeyImpl) {

            DSAPublicKeyImpl dsaPublicKeyImpl = (DSAPublicKeyImpl) publicKey;
            publicKeySize = dsaPublicKeyImpl.getParams().getP().bitLength();

        } else if (publicKey instanceof JDKDSAPublicKey) {

            JDKDSAPublicKey dsaPublicKeyImpl = (JDKDSAPublicKey) publicKey;
            publicKeySize = dsaPublicKeyImpl.getParams().getP().bitLength();
        } else {

            LOG.warning("Unknown public key infrastructure: " + publicKey.getClass().getName());
        }
        return publicKeySize;
    }
}
