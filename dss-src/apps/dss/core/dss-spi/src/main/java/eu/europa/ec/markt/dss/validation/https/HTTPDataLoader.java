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

package eu.europa.ec.markt.dss.validation.https;

import java.io.InputStream;
import java.io.Serializable;

import eu.europa.ec.markt.dss.exception.CannotFetchDataException;

/**
 * Component that permit to retrieve and post data using HTTP.
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public interface HTTPDataLoader extends Serializable {

    /**
     * Execute a HTTP GET operation
     *
     * @param URL
     * @return
     * @throws CannotFetchDataException
     */
    InputStream get(String URL) throws CannotFetchDataException;

    /**
     * Execute a HTTP POST operation
     *
     * @param URL
     * @param content
     * @return
     * @throws CannotFetchDataException
     */
    InputStream post(String URL, InputStream content) throws CannotFetchDataException;

}
