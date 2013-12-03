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

package eu.europa.ec.markt.dss.signature.xades;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import eu.europa.ec.markt.dss.signature.DSSDocument;

//import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;

/**
 * URIDereferencer is able to retrieve the data of the original file in the case of a detached signature or from the
 * signature file.
 *
 * NOTE: This dereferencer uses import org.jcp.xml.dsig.internal.dom.XMLDSigRI provider;
 *
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

// @SuppressWarnings("restriction")
public class ExternalFileURIDereferencer implements URIDereferencer {

    private static final Logger LOG = Logger.getLogger(ExternalFileURIDereferencer.class.getName());

    private final XMLSignatureFactory factory;

    // private final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

    private final String documentURI;

    private final DSSDocument document;

    /**
     * The default constructor for OneExternalFileURIDereferencer.
     */
    public ExternalFileURIDereferencer(DSSDocument document) {

        // try {
        // This provider support ECDSA signature
        factory = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        //
        // factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        // } catch (NoSuchProviderException e) {

        // throw new DSSException(e);
        // }
        this.documentURI = (document != null) ? document.getName() : null;
        this.document = document;
    }

    @Override
    public Data dereference(final URIReference uriReference, final XMLCryptoContext context) throws URIReferenceException {

        String uri = uriReference.getURI();
        // TODO: Following the test case: XAdESTest003 test: testTDetached() the URI can be like: should we accept this URI and what about the baseURI ?
        // <ds:Reference Id="Reference0" URI="./TARGET_BBB.bin">
        // The following rule was added to comply this functionality:
        // BEGIN:
        if (uri.startsWith("./")) {

            uri = uri.substring(2);
        }
        // :END
        if (!uri.equals(documentURI)) {

            final Data data = factory.getURIDereferencer().dereference(uriReference, context);
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info(
                      "--> Reference dereferenced: " + uriReference.getURI() + "=" + (data != null) + " | Reference type: " + uriReference.getType());
            }
            return data;
        }
        try {

            return new OctetStreamData(document.openStream());
        } catch (IOException e) {

            throw new RuntimeException(e);
        }
    }
}
