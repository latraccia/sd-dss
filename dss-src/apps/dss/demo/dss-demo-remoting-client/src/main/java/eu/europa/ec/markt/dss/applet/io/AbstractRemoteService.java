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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

/**
 * Service that transmit the execution of the operation to the server-backend.
 *
 * @param <REQ>
 * @param <RESP>
 * @version $Revision: 2937 $ - $Date: 2013-11-12 08:58:14 +0100 (mar., 12 nov. 2013) $
 */

public class AbstractRemoteService<REQ, RESP> {

    private String url;

    private HTTPDataLoader dataLoader;

    /**
     * @param dataLoader the dataLoader to set
     */
    public void setDataLoader(HTTPDataLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    /**
     * @param url the url to set
     */
    public void setUrl(String url) {
        this.url = url;
    }

    @SuppressWarnings("unchecked")
    protected RESP sendAndReceive(REQ message) throws IOException {

        if (dataLoader == null) {
            throw new NullPointerException("Must provide a HTTPDataLoader");
        }

        if (url == null) {
            throw new NullPointerException("The service URL cannot be null");
        }

        try {
            // the request/response objects are transported via the default java serialisation mechanism
            // see eu.europa.ec.markt.dss.applet.service.AbstractServiceHandler

            // marshall  
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            ObjectOutputStream output = new ObjectOutputStream(buffer);
            output.writeObject(message);
            output.close();

            InputStream inputStream = dataLoader.post(url, new ByteArrayInputStream(buffer.toByteArray()));

            // unmarshal
            ObjectInputStream input = new ObjectInputStream(inputStream);
            Object response = input.readObject();

            // check if exception occurred on the server-side.
            // if, then propagate (the stop is safe in this context, as the thread context is defined)
            if (response instanceof Exception) {

                // TODO: deprecated
                Thread.currentThread().stop((Exception) response);
            }
            return (RESP) response;
        } catch (ClassNotFoundException ex) {
            throw new IOException(ex);
        }
    }
}
