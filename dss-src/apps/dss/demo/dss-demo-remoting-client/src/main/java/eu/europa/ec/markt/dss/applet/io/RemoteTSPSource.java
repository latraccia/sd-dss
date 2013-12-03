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

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.applet.shared.TimestampRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.TimestampResponseMessage;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

import java.io.IOException;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * TSPSource that use the server backend for the operation execution (proxy).
 * 
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class RemoteTSPSource extends AbstractRemoteService<TimestampRequestMessage, TimestampResponseMessage>
        implements TSPSource {

    @Override
    public TimeStampResponse getTimeStampResponse(DigestAlgorithm algorithm, byte[] digest) throws IOException {

        try {
            TimestampRequestMessage request = new TimestampRequestMessage();
            request.setAlgorithm(algorithm.toString());
            request.setDigest(digest);

            TimestampResponseMessage response = sendAndReceive(request);

            return new TimeStampResponse(response.getTimestampResponse());
        } catch (TSPException ex) {
            throw new IOException(ex);
        }
    }

}
