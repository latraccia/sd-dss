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

package eu.europa.ec.markt.dss.validation102853.condition;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Condition that check a specific QCStatement
 *
 * @version $Revision: 1045 $ - $Date: 2011-06-27 11:07:14 +0200 (Mon, 27 Jun 2011) $
 */

public class QcStatementCondition extends Condition {

    private static final long serialVersionUID = -5504958938057542907L;

    private String qcStatementId = null;

    /**
     * The default constructor for QcStatementCondition.
     *
     * @param qcStatementId
     */
    public QcStatementCondition(final String qcStatementId) {

        this.qcStatementId = qcStatementId;
    }

    /**
     * The default constructor for QcStatementCondition.
     *
     * @param qcStatementId
     */
    public QcStatementCondition(final DERObjectIdentifier qcStatementId) {

        this(qcStatementId.getId());
    }

    /**
     * Checks the condition for the given certificate.
     *
     * @param cert certificate to be checked
     * @return
     */
    @Override
    public boolean check(final X509Certificate cert) {

        final byte[] qcStatement = cert.getExtensionValue(X509Extension.qCStatements.getId());
        if (qcStatement != null) {

            ASN1InputStream input = null;
            try {

                input = new ASN1InputStream(qcStatement);
                final DEROctetString s = (DEROctetString) input.readObject();
                final byte[] content = s.getOctets();
                input.close();
                input = new ASN1InputStream(content);
                final DERSequence seq = (DERSequence) input.readObject();
                /* Sequence of QCStatment */
                for (int ii = 0; ii < seq.size(); ii++) {

                    final QCStatement statement = QCStatement.getInstance(seq.getObjectAt(ii));
                    if (statement.getStatementId().getId().equals(qcStatementId)) {

                        return true;
                    }
                }
            } catch (IOException e) {

                throw new DSSException(e);
            } finally {

                DSSUtils.closeQuietly(input);
            }
        }
        return false;
    }

    @Override
    public String toString(String indent) {
        return null;
    }
}
