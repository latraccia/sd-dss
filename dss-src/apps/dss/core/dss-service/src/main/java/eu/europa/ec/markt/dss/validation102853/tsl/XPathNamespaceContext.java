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

import java.util.Iterator;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.NamespaceContext;

class XPathNamespaceContext implements NamespaceContext {

    @Override
    public String getNamespaceURI(String prefix) {

        if ("ds".equals(prefix)) {
            return XMLSignature.XMLNS;
        } else if ("etsi".equals(prefix)) {
            return "http://uri.etsi.org/01903/v1.1.1#";
        } else if ("xades".equals(prefix)) {
            return "http://uri.etsi.org/01903/v1.3.2#";
        } else if ("xades141".equals(prefix)) {
            return "http://uri.etsi.org/01903/v1.4.1#";
        }
        throw new RuntimeException("Prefix not recognized : " + prefix);
    }

    @Override
    public String getPrefix(String namespaceURI) {

        throw new RuntimeException();
    }

    @Override
    public Iterator<?> getPrefixes(String namespaceURI) {

        throw new RuntimeException();
    }
};
