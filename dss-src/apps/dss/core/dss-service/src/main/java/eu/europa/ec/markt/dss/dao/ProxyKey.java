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
package eu.europa.ec.markt.dss.dao;

/**
 * 
 * Keys for retrieving Proxy preferences information
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public enum ProxyKey {

    HTTPS_HOST("proxy.https.host"), HTTPS_PORT("proxy.https.port"), HTTPS_USER("proxy.https.user"), HTTPS_PASSWORD("proxy.https.password"), HTTPS_ENABLED("proxy.https.enabled"),

    HTTP_HOST("proxy.http.host"), HTTP_PORT("proxy.http.port"), HTTP_USER("proxy.http.user"), HTTP_PASSWORD("proxy.http.password"), HTTP_ENABLED("proxy.http.enabled");

    public static ProxyKey fromKey(String key) {

        if (ProxyKey.HTTP_ENABLED.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTP_ENABLED;
        } else if (ProxyKey.HTTP_HOST.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTP_HOST;
        } else if (ProxyKey.HTTP_PASSWORD.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTP_PASSWORD;
        } else if (ProxyKey.HTTP_PORT.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTP_PORT;
        } else if (ProxyKey.HTTP_USER.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTP_USER;
        } else if (ProxyKey.HTTPS_ENABLED.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTPS_ENABLED;
        } else if (ProxyKey.HTTPS_HOST.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTPS_HOST;
        } else if (ProxyKey.HTTPS_PASSWORD.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTPS_PASSWORD;
        } else if (ProxyKey.HTTPS_PORT.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTPS_PORT;
        } else if (ProxyKey.HTTPS_USER.key.equalsIgnoreCase(key)) {
            return ProxyKey.HTTPS_USER;
        } else {
            return null;
        }

    }

    private final String key;

    ProxyKey(final String key) {
        this.key = key;
    }
    
    public String getKey() {
		return key;
	}

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return this.key;
    }

}
