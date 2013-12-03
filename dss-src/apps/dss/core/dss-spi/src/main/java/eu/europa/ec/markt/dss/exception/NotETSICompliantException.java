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

package eu.europa.ec.markt.dss.exception;

import java.util.ResourceBundle;

/**
 * Occurs when something don't respect the ETSI specification
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class NotETSICompliantException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/ec/markt/dss/i18n");

    private MSG key;

    private String more;

    /**
     * Supported messages
     */
    public enum MSG {
        TSL_NOT_SIGNED, MORE_THAN_ONE_SIGNATURE, SIGNATURE_INVALID, NOT_A_VALID_XML,

        UNRECOGNIZED_TAG, UNSUPPORTED_ASSERT,

        XADES_DIGEST_ALG_AND_VALUE_ENCODING,

        ASICS_CADES, NO_SIGNING_TIME, NO_SIGNING_CERTIFICATE
    }

    /**
     * The default constructor for NotETSICompliantException.
     *
     * @param message
     */
    public NotETSICompliantException(final MSG message) {

        init(message);
    }

    /**
     * The default constructor for NotETSICompliantException.
     *
     * @param message
     */
    public NotETSICompliantException(final MSG message, final String more) {

        init(message);
        this.more = more;
    }

    public NotETSICompliantException(final MSG message, final Throwable cause) {
        super(cause);
        init(message);
    }

    private void init(MSG message) {
        if (message == null) {

            throw new IllegalArgumentException("Cannot build Exception without a message");
        }
        this.key = message;
    }

    @Override
    public String getLocalizedMessage() {

        final String bundleString = bundle.getString(key.toString());
        return bundleString + ((more != null) ? " / " + more : "");
    }

    @Override
    public String getMessage() {

        return getLocalizedMessage();
    }
}
