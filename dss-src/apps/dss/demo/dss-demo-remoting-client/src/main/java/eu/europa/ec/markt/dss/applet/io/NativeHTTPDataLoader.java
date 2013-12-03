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

package eu.europa.ec.markt.dss.applet.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

import org.apache.commons.io.IOUtils;

import eu.europa.ec.markt.dss.exception.CannotFetchDataException;
import eu.europa.ec.markt.dss.exception.CannotFetchDataException.MSG;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

/**
 * Implementation of HTTPDataLoader that use the java.net.URL class.
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class NativeHTTPDataLoader implements HTTPDataLoader {

    private static final long MAX_SIZE = 15000;

    /**
     * Used to limit the size of fetched data.
     */
    private class MaxSizeInputStream extends InputStream {

        private long maxSize;

        private InputStream wrappedStream;

        private long count = 0;

        private String url;

        /**
         * The default constructor for NativeHTTPDataLoader.MaxSizeInputStream.
         */
        public MaxSizeInputStream(InputStream wrappedStream, long maxSize, String url) {
            this.maxSize = maxSize;
            this.wrappedStream = wrappedStream;
            this.url = url;
        }

        @Override
        public int read() throws IOException {
            if (maxSize != 0) {
                count++;
                if (count > maxSize) {
                    throw new CannotFetchDataException(MSG.SIZE_LIMIT_EXCEPTION, url);
                }
            }
            return wrappedStream.read();
        }

    }

    @Override
    public InputStream get(String url) throws CannotFetchDataException {
        try {
            return new MaxSizeInputStream(new URL(url).openStream(), MAX_SIZE, url);
        } catch (IOException ex) {
            throw new CannotFetchDataException(ex, url);
        }
    }

    @Override
    public InputStream post(String url, InputStream content) throws CannotFetchDataException {

        try {
            URLConnection connection = new URL(url).openConnection();

            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setUseCaches(false);

            OutputStream out = connection.getOutputStream();
            IOUtils.copy(content, out);
            out.close();

            return connection.getInputStream();
        } catch (IOException ex) {

            throw new DSSException(url, ex);
        }
    }

}
