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

package eu.europa.ec.markt.dss.signature.provider;

import java.security.Provider;

/**
 * Provider for the SignatureInterceptor
 * 
 * 
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

@SuppressWarnings("serial")
public class SignatureInterceptorProvider extends Provider {

    public static String NAME = "SignatureInterceptor";

    private Provider legacy = null;

    /**
     * The default constructor for SignatureInterceptorProvider.
     */
    public SignatureInterceptorProvider() {
        super(NAME, 1.0, "Signature Interceptor Provider");
        put("Signature.SHA1withRSA", SignatureInterceptor.class.getName());
    }

    /**
     * 
     * The default constructor for SignatureInterceptorProvider.
     * 
     * @param legacy
     */
    public SignatureInterceptorProvider(Provider legacy) {
        super(NAME, 1.0, "Signature Interceptor Provider");
        this.legacy = legacy;
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
        if (legacy != null) {
            return legacy.getService(type, algorithm);
        }
        return super.getService(type, algorithm);
    }

}
