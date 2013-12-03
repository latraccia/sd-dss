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

import java.util.Arrays;
import java.util.Iterator;

import javax.xml.crypto.Data;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

class TSLURIDereferencer implements URIDereferencer {

    private static XPathNamespaceContext xPathNamespaceContext = new XPathNamespaceContext();

    private final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

    private Element signatureEl;

    public TSLURIDereferencer(Element signatureEl) {

        this.signatureEl = signatureEl;
    }

    /**
     * Creates the XPath expression based on the XPath string parameter.
     *
     * @param xpathString
     * @return
     */
    private XPathExpression createXPathExpression(String xpathString) {

		/* XPath */
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(xPathNamespaceContext);
        try {

            return xpath.compile(xpathString);
        } catch (XPathExpressionException e) {

            throw new RuntimeException(e);
        }
    }

    /**
     * Return the Element corresponding the the XPath
     *
     * @param xmlNode
     * @param xpathString
     * @return
     * @throws XPathExpressionException
     */
    private Element getElement(Node xmlNode, String xpathString) {

        XPathExpression expr = createXPathExpression(xpathString);
        try {

            NodeList list = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
            if (list.getLength() > 1) {

                throw new RuntimeException("More than one result for XPath: " + xpathString);
            }
            return (Element) list.item(0);
        } catch (XPathExpressionException e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {

        try {

            Data data = factory.getURIDereferencer().dereference(uriReference, context);
            // if (LOG.isLoggable(Level.INFO)) LOG.info("Reference checked: " + reference.getURI() + "=" + refHashValidity);
            System.out.println(
                  "--> Reference dereferenced: " + uriReference.getURI() + "=" + (data != null) + " | Reference type: " + uriReference
                        .getType());
            return data;
        } catch (URIReferenceException e) {

            if (uriReference.getType().equals("http://uri.etsi.org/01903/v1.1.1#SignedProperties")) {

                // XAdESSignature.XPATH_SIGNED_PROPERTIES
                final Element signedProperties = getElement(signatureEl, "./ds:Object/xades:QualifyingProperties/xades:SignedProperties");
                if (signedProperties != null) {
                    return new NodeSetData() {

                        @Override
                        public Iterator<?> iterator() {

                            return Arrays.asList(signedProperties).iterator();
                        }
                    };
                }
                final Element signedProperties111 = getElement(signatureEl, "./ds:Object/etsi:QualifyingProperties/etsi:SignedProperties");
                if (signedProperties111 != null) {
                    return new NodeSetData() {

                        @Override
                        public Iterator<?> iterator() {

                            return Arrays.asList(signedProperties111).iterator();
                        }
                    };
                }
            }
            throw e;
        }
    }
}
