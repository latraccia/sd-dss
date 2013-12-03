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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import eu.europa.ec.markt.dss.DigestAlgorithm;

/**
 * Connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public interface SignatureTokenConnection {

   /**
    * Closes the connection to the SSCD.
    */
   void close();

   /**
    * Retrieves all the available keys (private keys entries) from the SSCD.
    * 
    * @return
    * @throws KeyStoreException
    */
   List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException;

   /**
    * Signs the stream with the private key.
    * 
    * @param stream The stream that need to be signed
    * @param signatureAlgo
    * @param digestAlgo
    * @param keyEntry
    * @return
    * @throws NoSuchAlgorithmException If the algorithm is not supported
    * @throws IOException the token cannot produce the signature
    */
   byte[] sign(final InputStream stream, final DigestAlgorithm digestAlgo, final DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException, IOException;

}