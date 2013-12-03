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

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.applet.shared.TimestampRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.TimestampResponseMessage;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

import java.io.IOException;
import java.util.logging.Logger;

import org.bouncycastle.tsp.TimeStampResponse;

/**
 * Create a TimeStamp with the wrapped TSPSource
 * 
 *
 * @version $Revision: 994 $ - $Date: 2011-06-16 18:01:17 +0200 (jeu., 16 juin 2011) $
 */

public class TimestampRequestHandler extends
        AbstractServiceHandler<TimestampRequestMessage, TimestampResponseMessage> {

    private static final Logger LOG = Logger.getLogger(TimestampRequestHandler.class.getName());

    private TSPSource tspSource;

    /**
     * @param tspSource the tspSource to set
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    @Override
    protected TimestampResponseMessage handleRequest(TimestampRequestMessage message) throws IOException {

        TimeStampResponse resp = tspSource.getTimeStampResponse(DigestAlgorithm.valueOf(message.getAlgorithm()),
                message.getDigest());

        TimestampResponseMessage response = new TimestampResponseMessage();
        response.setTimestampResponse(resp.getEncoded());
        return response;
    }

}
