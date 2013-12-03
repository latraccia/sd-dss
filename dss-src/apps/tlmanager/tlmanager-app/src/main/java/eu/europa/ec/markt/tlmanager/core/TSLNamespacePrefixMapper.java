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

package eu.europa.ec.markt.tlmanager.core;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * Defines the generally used prefixes and namespaces.
 * 
 *
 * @version $Revision: 1168 $ - $Date: 2012-03-05 12:28:27 +0100 (lun., 05 mars 2012) $
 */

public class TSLNamespacePrefixMapper extends NamespacePrefixMapper {

    private static final Logger LOG = Logger.getLogger(TSLNamespacePrefixMapper.class.getName());

    private static final Map<String, String> prefixes = new HashMap<String, String>();

    static {
        prefixes.put("http://uri.etsi.org/02231/v2#", "tsl");
        prefixes.put("http://www.w3.org/2000/09/xmldsig#", "ds");
        prefixes.put("http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#", "ecc");
        prefixes.put("http://uri.etsi.org/01903/v1.3.2#", "xades");
        prefixes.put("http://uri.etsi.org/02231/v2/additionaltypes#", "tslx");
    }

    // <?xml version="1.0" encoding="UTF-8"?><!-- TSL en XML generada por TSLGenerator de MITYC -->
    // <!-- Editada por Asistencia técnica --><tsl:TrustServiceStatusList
    // xmlns:tsl="http://uri.etsi.org/02231/v2#"
    // xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    // xmlns:ecc="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
    // xmlns:tslx="http://uri.etsi.org/02231/v2/additionaltypes#"
    // xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"
    // xmlns:xi="http://www.w3.org/2001/XInclude"
    // xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Id="TSL20101222100123"
    // TSLTag="http://uri.etsi.org/02231/TSLTag" xsi:schemaLocation="http://uri.etsi.org/02231/v2#    " +
    // "http://uri.etsi.org/02231/v3.1.2/ts_102231v030102_xsd.xsd    " +
    // " http://uri.etsi.org/02231/v2/additionaltypes#     " +
    // "http://uri.etsi.org/02231/v3.1.2/ts_102231v030102_additionaltypes_xsd.xsd     " +
    // "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#   " +
    // " http://uri.etsi.org/02231/v3.1.2/ts_102231v030102_sie_xsd.xsd">
    @Override
    public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
        LOG.log(Level.FINE, "NamespaceURI {0} - Suggestion {1} - RequirePrefix {2}", new Object[] { namespaceUri,
                suggestion, requirePrefix });

        String prefix = prefixes.get(namespaceUri);
        if (null != prefix) {
            return prefix;
        }
        return suggestion;
    }
}