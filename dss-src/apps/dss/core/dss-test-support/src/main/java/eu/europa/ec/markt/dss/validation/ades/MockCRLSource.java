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

package eu.europa.ec.markt.dss.validation.ades;

import eu.europa.ec.markt.dss.exception.DSSException;

import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

/**
 * @version $Revision: 2449 $ - $Date: 2013-08-28 07:21:25 +0200 (Wed, 28 Aug 2013) $
 */

public class MockCRLSource extends SignatureCRLSource {

    private List<X509CRL> list = new ArrayList<X509CRL>();

    /**
     * The default constructor for MockCRLSource.
     */
    public MockCRLSource(String... path) {
        try {
            for (String pathItem : path) {
                InputStream crlFileRepository = getClass().getResourceAsStream(pathItem);
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                X509CRL x509CRL = (X509CRL) factory.generateCRL(crlFileRepository);
                list.add(x509CRL);
            }
        } catch (CertificateException ex) {
            throw new DSSException(ex);
        } catch (CRLException ex) {
            throw new DSSException(ex);
        }
    }

    @Override
    public List<X509CRL> getContainedCRLs() {

        return list.size() > 0 ? list : null;
    }

}
