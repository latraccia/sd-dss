/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.applet.service;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.ParameterizedType;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.HttpRequestHandler;

/**
 * Handle the generic aspects of a request in DSS. This serialize/deserialize the byte stream in objects comprehensible
 * by DSS.
 * 
 * 
 * @version $Revision: 1433 $ - $Date: 2012-11-22 14:34:21 +0100 (jeu., 22 nov. 2012) $
 * @param <REQ>
 * @param <RESP>
 */

public abstract class AbstractServiceHandler<REQ, RESP> implements HttpRequestHandler {

    private static final Logger LOG = Logger.getLogger(AbstractServiceHandler.class.getName());

    private Class<REQ> reqClazz;

    @SuppressWarnings("unchecked")
    public AbstractServiceHandler() {
        this.reqClazz = (Class<REQ>) ((ParameterizedType) this.getClass().getGenericSuperclass())
                .getActualTypeArguments()[0];
    }

    /**
     * Handle the HTTP request and serialize the response in the HTTP response.
     */
    // @SuppressWarnings("unchecked")
    @Override
    public void handleRequest(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        // Object responseMessage = null;
        // Kryo kryo = new Kryo();
        // Input input = new Input(req.getInputStream());
        // Output output = new Output(resp.getOutputStream());
        // REQ message = kryo.readObject(input, reqClazz);
        // try {
        // responseMessage = handleRequest(message);
        // } catch (Exception ex) {
        // responseMessage = ex;
        // } finally {
        // kryo.writeObject(output, responseMessage);
        // }

        try {
            // the request/response *objects* are transported via the default java serialisation mechanism
            // see eu.europa.ec.markt.dss.applet.io.AbstractRemoteService

            // unmarshall
            ObjectInputStream input = new ObjectInputStream(req.getInputStream());
            REQ message = (REQ) input.readObject();

            Object responseMessage;
            try {
                responseMessage = handleRequest(message);
            } catch (Exception ex) {
                responseMessage = ex;
            }

            // marshall
            ObjectOutputStream output = new ObjectOutputStream(resp.getOutputStream());
            output.writeObject(responseMessage);
            output.close();
            
        } catch (ClassNotFoundException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new IOException("Unknown object in byte stream", ex);
        }

    }

    /**
     * Handle the DSS request itself and produce the response object that will be serialized in the HTTP response
     * stream.
     * 
     * @param message
     * @return
     * @throws IOException
     */
    protected abstract RESP handleRequest(REQ message) throws IOException;

}
