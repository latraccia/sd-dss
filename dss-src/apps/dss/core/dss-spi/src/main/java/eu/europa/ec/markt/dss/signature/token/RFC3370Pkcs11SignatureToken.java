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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.BadPasswordException;
import eu.europa.ec.markt.dss.exception.BadPasswordException.MSG;
import eu.europa.ec.markt.dss.exception.ConfigurationException;

/**
 * PKCS11 token with callback.<br>
 * This class was created following a different interpretation of the RFC 3370 standard by some member states. In the
 * current era it is advisable to use MOCCA
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */
@Deprecated
public class RFC3370Pkcs11SignatureToken extends AsyncSignatureTokenConnection {

    private Provider _pkcs11Provider;

    private String pkcs11Path;

    private KeyStore _keyStore;

    final private PasswordInputCallback callback;

    private int slotIndex;

    /**
     * Create the SignatureTokenConnection, using the provided path for the library.
     *
     * @param pkcs11Path
     */
    public RFC3370Pkcs11SignatureToken(String pkcs11Path) {
        this(pkcs11Path, (PasswordInputCallback) null);
        this.slotIndex = 0;
    }

    /**
     * Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the password
     * from the user. The default constructor for CallbackPkcs11SignatureToken.
     *
     * @param pkcs11Path
     * @param callback
     */
    public RFC3370Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback) {
        this.pkcs11Path = pkcs11Path;
        this.callback = callback;
        this.slotIndex = 0;
    }

    /**
     * Sometimes, the password is known in advance. This create a SignatureTokenConnection and the keys will be accessed
     * using the provided password. The default constructor for CallbackPkcs11SignatureToken.
     *
     * @param pkcs11Path
     * @param password
     */
    public RFC3370Pkcs11SignatureToken(String pkcs11Path, char[] password) {
        this(pkcs11Path, new PrefilledPasswordCallback(password));
        this.slotIndex = 0;
    }

    /**
     * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
     * This create a SignatureTokenConnection and the keys will be accessed using the provided password.
     *
     * @param pkcs11Path
     * @param callback
     * @param slotIndex
     */
    public RFC3370Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotIndex) {
        this(pkcs11Path, callback);
        this.slotIndex = slotIndex;
    }

    /**
     * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
     * This Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the
     * password from the user.
     *
     * @param pkcs11Path
     * @param password
     * @param slotIndex
     */
    public RFC3370Pkcs11SignatureToken(String pkcs11Path, char[] password, int slotIndex) {
        this(pkcs11Path, password);
        this.slotIndex = slotIndex;
    }

    @SuppressWarnings("restriction")
    private Provider getProvider() {
        try {
            if (_pkcs11Provider == null) {
                String aPKCS11LibraryFileName = getPkcs11Path();
                String pkcs11ConfigSettings = "name = SmartCard\n" + "library = " + aPKCS11LibraryFileName + "\nslotListIndex = " + slotIndex;
                byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
                ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

                sun.security.pkcs11.SunPKCS11 pkcs11 = new sun.security.pkcs11.SunPKCS11(confStream);
                _pkcs11Provider = (Provider) pkcs11;

                Security.addProvider(_pkcs11Provider);
            }
            return _pkcs11Provider;
        } catch (ProviderException ex) {
            throw new ConfigurationException(ConfigurationException.MSG.NOT_PKCS11_LIB, ex);
        }

    }

    @SuppressWarnings("restriction")
    private KeyStore getKeyStore() throws KeyStoreException {
        if (_keyStore == null) {
            _keyStore = KeyStore.getInstance("PKCS11", getProvider());
            try {
                _keyStore.load(new KeyStore.LoadStoreParameter() {

                    @Override
                    public ProtectionParameter getProtectionParameter() {
                        return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

                            @Override
                            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                                for (Callback c : callbacks) {
                                    if (c instanceof PasswordCallback) {
                                        ((PasswordCallback) c).setPassword(callback.getPassword());
                                        return;
                                    }
                                }
                                throw new RuntimeException("No password callback");
                            }
                        });
                    }
                });
            } catch (Exception e) {
                if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
                    if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
                        throw new BadPasswordException(MSG.PKCS11_BAD_PASSWORD, e);
                    }
                }
                throw new KeyStoreException("Can't initialize Sun PKCS#11 security " + "provider. Reason: " + getCauseMessage(e), e);
            }
        }
        return _keyStore;
    }

    private String getPkcs11Path() {
        return pkcs11Path;
    }

    @Override
    public void close() {
        if (_pkcs11Provider != null) {
            try {
                Security.removeProvider(_pkcs11Provider.getName());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        this._pkcs11Provider = null;
        this._keyStore = null;
    }

    @Override
    public byte[] encryptDigest(final byte[] digestValue, final DigestAlgorithm digestAlgo,
                                final DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException {

        try {
            final ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
            switch (digestAlgo) {
                case SHA1:
                    digestInfo.write(Constants.SHA1_DIGEST_INFO_PREFIX);
                    break;
                case SHA224:
                    digestInfo.write(Constants.SHA224_DIGEST_INFO_PREFIX);
                    break;
                case SHA256:
                    digestInfo.write(Constants.SHA256_DIGEST_INFO_PREFIX);
                    break;
                case SHA384:
                    digestInfo.write(Constants.SHA384_DIGEST_INFO_PREFIX);
                    break;
                case SHA512:
                    digestInfo.write(Constants.SHA512_DIGEST_INFO_PREFIX);
                    break;
                case RIPEMD160:
                    digestInfo.write(Constants.RIPEMD160_DIGEST_INFO_PREFIX);
                    break;
                case MD2:
                    break;
                case MD5:
                    digestInfo.write(Constants.MD5_DIGEST_INFO_PREFIX);
                    break;
            }
            digestInfo.write(digestValue);
            final byte[] infoBytes = digestInfo.toByteArray();

            final Cipher cipher = Cipher.getInstance(keyEntry.getEncryptionAlgorithm().getPadding());
            cipher.init(Cipher.ENCRYPT_MODE, ((KSPrivateKeyEntry) keyEntry).getPrivateKey());
            return cipher.doFinal(infoBytes);
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException {

        List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

        try {
            KeyStore keyStore = getKeyStore();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, null);
                    list.add(new KSPrivateKeyEntry(entry));
                }
            }

        } catch (Exception e) {
            throw new KeyStoreException("Can't initialize Sun PKCS#11 security " + "provider. Reason: " + getCauseMessage(e), e);
        }

        return list;
    }
}
