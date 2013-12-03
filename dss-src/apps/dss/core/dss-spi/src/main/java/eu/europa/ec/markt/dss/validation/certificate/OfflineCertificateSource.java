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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * Some certificate source are "offline", that means that the set of certificate is availaible and the software only
 * needs to find the certificate on base of the subjectName
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public abstract class OfflineCertificateSource implements CertificateSource {

    private CertificateSourceType sourceType;

    /**
     * @param sourceType the sourceType to set
     */
    public void setSourceType(CertificateSourceType sourceType) {
        this.sourceType = sourceType;
    }

    @Override
    final public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {
        List<CertificateAndContext> list = new ArrayList<CertificateAndContext>();
        for (X509Certificate cert : getCertificates()) {
            if (subjectName.equals(cert.getSubjectX500Principal())) {
                CertificateAndContext cc = new CertificateAndContext(cert);
                cc.setCertificateSource(sourceType);
                list.add(cc);
            }
        }
        return list;
    }

    /**
     * Retrieve the list of certificate from this source.
     * 
     * @return
     */
    public abstract List<X509Certificate> getCertificates();

}
