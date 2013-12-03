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
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;

/**
 * Class holding all MS CAPI API access logic.
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class MSCAPISignatureToken implements SignatureTokenConnection {

	private static class CallbackPasswordProtection extends KeyStore.PasswordProtection {
		PasswordInputCallback passwordCallback;

		public CallbackPasswordProtection(PasswordInputCallback callback) {
			super(null);
			this.passwordCallback = callback;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.security.KeyStore.PasswordProtection#getPassword()
		 */
		@Override
		public synchronized char[] getPassword() {
			if (passwordCallback == null) {
				throw new RuntimeException("MSCAPI: No callback provided for entering the PIN/password");
			}
			char[] password = passwordCallback.getPassword();
			return password;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection#close()
	 */
	@Override
	public void close() {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection#sign( java.io.InputStream,
	 * eu.europa.ec.markt.dss.DigestAlgorithm, eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry)
	 */
	@Override
	public byte[] sign(InputStream stream, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry) throws IOException, NoSuchAlgorithmException {

		try {

			EncryptionAlgorithm encryptionAlgo = keyEntry.getEncryptionAlgorithm();
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgo, digestAlgo);
			Signature signature = Signature.getInstance(signatureAlgorithm.getJAVAId());
			signature.initSign(((KSPrivateKeyEntry) keyEntry).getPrivateKey());
			byte[] buffer = new byte[4096];
			int count = 0;
			while ((count = stream.read(buffer)) > 0) {
				signature.update(buffer, 0, count);
			}
			return signature.sign();
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * This method is a workaround for scenarios when multiple entries have the same alias. Since the alias is the only "official"
	 * way of retrieving an entry, only the first entry with a given alias is accessible.
	 * 
	 * @param keyStore the key store to fix
	 */
	private static void _fixAliases(KeyStore keyStore) {
		Field field;
		KeyStoreSpi keyStoreVeritable;

		try {
			field = keyStore.getClass().getDeclaredField("keyStoreSpi");
			field.setAccessible(true);
			keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

			if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
				Collection<?> entries;
				String alias, hashCode;
				X509Certificate[] certificates;

				field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
				field.setAccessible(true);
				entries = (Collection<?>) field.get(keyStoreVeritable);

				for (Object entry : entries) {
					field = entry.getClass().getDeclaredField("certChain");
					field.setAccessible(true);
					certificates = (X509Certificate[]) field.get(entry);

					hashCode = Integer.toString(certificates[0].hashCode());

					field = entry.getClass().getDeclaredField("alias");
					field.setAccessible(true);
					alias = (String) field.get(entry);

					if (!alias.equals(hashCode)) {
						field.set(entry, alias.concat(" - ").concat(hashCode));
					}
				}
			}
		} catch (Exception exception) {
			System.err.println(exception);
			exception.printStackTrace();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection#getKeys()
	 */
	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException {

		List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

		try {
			ProtectionParameter protectionParameter = new CallbackPasswordProtection(new PrefilledPasswordCallback("nimp".toCharArray()));

			KeyStore keyStore = KeyStore.getInstance("Windows-MY");
			keyStore.load(null, null);
			_fixAliases(keyStore);

			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias)) {
					PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, protectionParameter);
					list.add(new KSPrivateKeyEntry(entry));
				}
			}

		} catch (Exception e) {
			throw new KeyStoreException(e);
		}

		return list;
	}
}
