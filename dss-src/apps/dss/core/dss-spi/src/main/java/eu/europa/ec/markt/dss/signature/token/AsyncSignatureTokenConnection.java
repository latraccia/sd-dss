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

package eu.europa.ec.markt.dss.signature.token;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Logger;

import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;

/**
 * Sometimes, the signature process has to be split in two phases : the digest phase and the encryption phase. This
 * separation is useful when the file and the SSCD are not on the same hardware. Two implementations of
 * AsyncSignatureTokenConnection are provided. Only MSCAPI requires the signature to be done in one step (MS CAPI
 * doesn't provide any RSA encryption operations).
 *
 * @version $Revision: 1835 $ - $Date: 2013-03-12 09:54:17 +0100 (Tue, 12 Mar 2013) $
 */

public abstract class AsyncSignatureTokenConnection implements SignatureTokenConnection {

    protected static final Logger LOG = Logger.getLogger(AsyncSignatureTokenConnection.class.getName());

    protected static String getCauseMessage(final Exception e) {
        return (e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
    }

    /**
     * The encryption of a digest is the atomic operation done by the SSCD. This encryption (RSA, DSA, ...) creates the
     * signature value.
     *
     * @param digestValue
     * @param digestAlgo
     * @param keyEntry
     * @return
     */
    abstract public byte[] encryptDigest(byte[] digestValue, DigestAlgorithm digestAlgo,
                                         DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException;

    /**
     * The encryption of a digest is the atomic operation done by the SSCD. This encryption (RSA, DSA, ...) creates the
     * signature value.
     *
     * @param digest
     * @param keyEntry
     * @return
     * @throws NoSuchAlgorithmException
     */
    public byte[] encryptDigest(Digest digest, DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException {

        return this.encryptDigest(digest.getValue(), digest.getAlgorithm(), keyEntry);
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection#sign( java.io.InputStream,
     * eu.europa.ec.markt.dss.DigestAlgorithm, eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry)
     */
    @Override
    public byte[] sign(final InputStream stream, final DigestAlgorithm digestAlgo,
                       final DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException, IOException {

        final EncryptionAlgorithm encryptionAlgo = keyEntry.getEncryptionAlgorithm();
        LOG.info("Encryption algorithm: " + encryptionAlgo);
        if (EncryptionAlgorithm.RSA.equals(encryptionAlgo)) {

            final MessageDigest digester = MessageDigest.getInstance(digestAlgo.getName());
            final byte[] buffer = new byte[4096];
            int count = 0;
            while ((count = stream.read(buffer)) > 0) {

                digester.update(buffer, 0, count);
            }
            final byte[] digestValue = digester.digest();
            return encryptDigest(digestValue, digestAlgo, keyEntry);
        } else {

            final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgo, digestAlgo);
            LOG.info("Signing with: " + signatureAlgorithm.getJAVAId());
            final Signature signature = Signature.getInstance(signatureAlgorithm.getJAVAId());
            try {

                signature.initSign(((KSPrivateKeyEntry) keyEntry).getPrivateKey());
                final byte[] buffer = new byte[4096];
                int count = 0;
                while ((count = stream.read(buffer)) > 0) {

                    signature.update(buffer, 0, count);
                }
                final byte[] signValue = signature.sign();
                return signValue;
            } catch (SignatureException e) {

                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {

                throw new RuntimeException(e);
            }
        }
    }
}