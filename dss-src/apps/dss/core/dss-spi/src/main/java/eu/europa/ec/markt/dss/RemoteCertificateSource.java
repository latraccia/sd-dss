/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas BovÃ© 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * This interface defines the remote source of certificates.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public interface RemoteCertificateSource {

    /**
     * Define the URL of the service providing certificates
     *
     * @param serviceUrl the serviceUrl to set
     */
    public void setServiceUrl(String serviceUrl);

    /**
     * The data loader implementing the transport layer used when retrieving the certificate.
     *
     * @param dataLoader the dataLoader to set
     */
    public void setDataLoader(HTTPDataLoader dataLoader);

    /**
     * This method returns the <code>List</code> of <code>CertificateToken</code>(s) corresponding to the given subject distinguished name.
     * The search is performed at the level of source and not at the pool level (The same pool can be shared by many sources).
     *
     * @param x500Principal subject distinguished names of the certificate to find
     * @return
     */
    public List<CertificateToken> get(final X500Principal x500Principal);
}
