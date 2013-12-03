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

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.DigestInfo;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.BadPasswordException;
import eu.europa.ec.markt.dss.exception.BadPasswordException.MSG;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Class holding all Java KeyStore file access logic.
 *
 * @version $Revision: 980 $ - $Date: 2011-06-16 14:17:13 +0200 (jeu., 16 juin 2011) $
 */

public class JKSSignatureToken extends AsyncSignatureTokenConnection {

    private char[] password;

    protected KeyStore keyStore = null;

    /**
     * Creates a SignatureTokenConnection with the provided path to Java KeyStore file and password.
     *
     * @param ksUrlLocation
     * @param ksPassword
     */
    public JKSSignatureToken(String ksUrlLocation, String ksPassword) {

        InputStream ksStream = null;
        try {

            final URL ksLocation = new URL(ksUrlLocation);
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            ksStream = ksLocation.openStream();
            keyStore.load(ksStream, (ksPassword == null) ? null : ksPassword.toCharArray());
        } catch (Exception e) {

            throw new DSSException("Can not access Java KeyStore. Reason: " + getCauseMessage(e), e);
        } finally {

            DSSUtils.closeQuietly(ksStream);
        }
    }

    @Override
    public void close() {
    }

    @Override
    public byte[] encryptDigest(byte[] digestValue, DigestAlgorithm digestAlgo,
                                DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException {

        try {

            final DigestInfo digestInfo = new DigestInfo(digestAlgo.getAlgorithmIdentifier(), digestValue);
            final Cipher cipher = Cipher.getInstance(keyEntry.getEncryptionAlgorithm().getPadding());
            cipher.init(Cipher.ENCRYPT_MODE, ((KSPrivateKeyEntry) keyEntry).getPrivateKey());
            return cipher.doFinal(digestInfo.getDEREncoded());
        } catch (BadPaddingException e) {
            throw new BadPasswordException(MSG.JAVA_KEYSTORE_BAD_PASSWORD, e);
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    /**
     * Retrieves all the available keys (private keys entries) from the Java KeyStore.
     *
     * @return
     * @throws KeyStoreException
     */
    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException {

        final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

        try {
            final PasswordProtection pp = new KeyStore.PasswordProtection(password);
            final Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {

                final String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {

                    final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, pp);
                    list.add(new KSPrivateKeyEntry(entry));
                }
            }
        } catch (Exception e) {

            throw new KeyStoreException("Can't get private keys. Reason: " + getCauseMessage(e), e);
        }
        return list;
    }
}
