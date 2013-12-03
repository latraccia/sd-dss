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

package eu.europa.ec.markt.dss.validation.certificate;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Creates a CertificateSource from a List or Array of Certificate.
 * 
 *
 * @version $Revision: 1457 $ - $Date: 2012-11-30 14:24:19 +0100 (ven., 30 nov. 2012) $
 */

public class ListCertificateSource extends OfflineCertificateSource {

    private List<X509Certificate> certificates;

    /**
     * The default constructor for ListCertificateSource.
     */
    public ListCertificateSource(List<X509Certificate> certificates) {
        this.certificates = certificates;
    }

    /**
     * The default constructor for ListCertificateSource.
     */
    public ListCertificateSource(X509Certificate[] certificates) {
        this(Arrays.asList(certificates));
    }

    /**
     * The default constructor for ListCertificateSource.
     */
    public ListCertificateSource(Certificate[] certificates) {
        this((X509Certificate[]) certificates);
    }

    @Override
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

}
