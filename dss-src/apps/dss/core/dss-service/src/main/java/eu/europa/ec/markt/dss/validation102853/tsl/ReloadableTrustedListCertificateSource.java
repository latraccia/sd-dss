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

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;

/**
 * This CertificateSource keep a list of trusted certificates extracted from the trusted list. To populate this list {@link
 * eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource} class is used. This list is refreshed when the method refresh
 * is called.
 *
 * @version $Revision: 2912 $ - $Date: 2013-11-10 22:48:01 +0100 (Sun, 10 Nov 2013) $
 */

public class ReloadableTrustedListCertificateSource extends TrustedListsCertificateSource {

    private static final Logger LOG = Logger.getLogger(ReloadableTrustedListCertificateSource.class.getName());

    private TrustedListsCertificateSource currentSource = new TrustedListsCertificateSource();

    public ReloadableTrustedListCertificateSource() {

        super();
    }

    static class Reloader implements Runnable {

        TrustedListsCertificateSource underlyingSource;

        Reloader(TrustedListsCertificateSource underlyingSource) {

            this.underlyingSource = underlyingSource;
        }

        @Override
        public void run() {

            try {

                LOG.info("Reload Trusted List");
                // Asynchronous loading of all the data in the TSLs
                System.out.println("--> START LOADING");
                underlyingSource.init();
                System.out.println("--> END LOADING");

            } catch (EncodingException e) {
                makATrace(e);
            }
        }

        private static void makATrace(Exception e) {

            e.printStackTrace();
            LOG.log(Level.SEVERE, "", e);
        }
    }

    public synchronized void refresh() {

        TrustedListsCertificateSource newSource = new TrustedListsCertificateSource(this);

        Thread reloader = new Thread(new Reloader(newSource));
        System.out.println("--> START");
        reloader.start();
        System.out.println("--> END");

        currentSource = newSource;
    }

    public Map<String, String> getDiagnosticInfo() {

        return currentSource.getDiagnosticInfo();
    }

    @Override
    public CertificatePool getCertificatePool() {

        System.out.println("--> ReloadableTrustedListCertificateSource ->getCertPool()");
        return currentSource.getCertificatePool();
    }
}
