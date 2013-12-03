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

package eu.europa.ec.markt.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.signature.DSSDocument;

/**
 * Utility class that contains some XML related method.
 *
 * @version $Revision: 2221 $ - $Date: 2013-06-11 11:53:27 +0200 (Tue, 11 Jun 2013) $
 */

public final class DSSXMLUtils {

    public static final String ID_ATTRIBUTE_NAME = "Id";

    private static DocumentBuilderFactory dbFactory;
    private static DocumentBuilder documentBuilder;

    private static final XPathFactory factory = XPathFactory.newInstance();

    private static final NamespaceContext namespacePrefixMapper;

    private static final Map<String, String> namespaces;

    static {

        namespaces = new HashMap<String, String>();
        namespaces.put("ds", XMLSignature.XMLNS);
        namespaces.put("xades", "http://uri.etsi.org/01903/v1.3.2#");
        namespaces.put("xades141", "http://uri.etsi.org/01903/v1.4.1#");
        namespaces.put("xades122", "http://uri.etsi.org/01903/v1.2.2#");
        namespaces.put("xades111", "http://uri.etsi.org/01903/v1.1.1#");

        namespacePrefixMapper = new NamespaceContextMap(namespaces);
    }

    /**
     * This class is an utility class and cannot be instantiated.
     */
    private DSSXMLUtils() {

    }

    /**
     * @param xpathString XPath query string
     * @return
     */
    private static XPathExpression createXPathExpression(final String xpathString) {

      /* XPath */
        final XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(namespacePrefixMapper);

        try {
            XPathExpression expr = xpath.compile(xpathString);
            return expr;
        } catch (XPathExpressionException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Return the Element corresponding to the XPath query.
     *
     * @param xmlNode     The node where the search should be performed.
     * @param xPathString XPath query string
     * @return
     */
    public static Element getElement(final Node xmlNode, final String xPathString) {

        final NodeList list = getNodeList(xmlNode, xPathString);
        if (list.getLength() > 1) {
            throw new RuntimeException("More than one result for XPath: " + xPathString);
        }
        return (Element) list.item(0);
    }

    /**
     * Return the Node corresponding to the XPath query.
     *
     * @param xmlNode     The node where the search should be performed.
     * @param xPathString XPath query string
     * @return
     */
    public static Node getNode(final Node xmlNode, final String xPathString) {

        final XPathExpression expr = createXPathExpression(xPathString);
        try {

            NodeList list = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
            if (list.getLength() > 1) {
                throw new RuntimeException("More than one result for XPath: " + xPathString);
            }
            return list.item(0);
        } catch (XPathExpressionException e) {
            throw new RuntimeException("XPath query problem: " + xPathString, e);
        }
    }

    /**
     * Returns the NodeList corresponding to the XPath query.
     *
     * @param xmlNode     The node where the search should be performed.
     * @param xPathString XPath query string
     * @return
     * @throws XPathExpressionException
     */
    public static NodeList getNodeList(final Node xmlNode, final String xPathString) {

        try {

            XPathExpression expr = createXPathExpression(xPathString);
            return (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {

            throw new RuntimeException(e);
        }
    }

    /**
     * @param xmlNode The node to be serialized.
     * @return
     */
    public static String serializeNode(final Node xmlNode) {

        try {

            final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            final LSSerializer writer = impl.createLSSerializer();

            final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            final LSOutput output = impl.createLSOutput();
            output.setByteStream(buffer);
            writer.write(xmlNode, output);

            return new String(buffer.toByteArray());
        } catch (Exception e) {
         /* Serialize node is for debugging only */
            return null;
        }
    }

    /**
     * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by
     * the fact that the attribute does not have attached type of information. Another solution is to parse the XML
     * against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
     *
     * @param context
     * @param element
     */
    public static void recursiveIdBrowse(final DOMValidateContext context, final Element element) {

        for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

            final Node node = element.getChildNodes().item(ii);
            if (node.getNodeType() == Node.ELEMENT_NODE) {

                final Element childElement = (Element) node;
                if (childElement.hasAttribute(ID_ATTRIBUTE_NAME)) {

                    context.setIdAttributeNS(childElement, null, ID_ATTRIBUTE_NAME);
                }
                recursiveIdBrowse(context, childElement);
            }
        }
    }

    /**
     * Guarantees that the xmlString builder has been created.
     *
     * @throws ParserConfigurationException
     */
    private static void ensureDocumentBuilder() throws ParserConfigurationException {

        if (dbFactory != null) {
            return;
        }
        dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        documentBuilder = dbFactory.newDocumentBuilder();
    }

    /**
     * Creates the new empty Document.
     *
     * @return
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     */
    public static Document buildDOM() throws ParserConfigurationException, IOException, SAXException {

        ensureDocumentBuilder();

        return documentBuilder.newDocument();
    }

    /**
     * This method returns the {@link org.w3c.dom.Document} created based on the XML string.
     *
     * @param xmlString The string representing the dssDocument to be created.
     * @return
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     */
    public static Document buildDOM(final String xmlString) throws ParserConfigurationException, IOException, SAXException {

        final InputStream input = new ByteArrayInputStream(xmlString.getBytes());
        return buildDOM(input);
    }

    /**
     * This method returns the {@link org.w3c.dom.Document} created based on byte array.
     *
     * @param document The bytes array representing the dssDocument to be created.
     * @return
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     */
    public static Document buildDOM(final byte[] document) throws ParserConfigurationException, IOException, SAXException {

        final InputStream input = new ByteArrayInputStream(document);
        return buildDOM(input);
    }

    /**
     * This method returns the {@link org.w3c.dom.Document} created based on the XML inputStream.
     *
     * @param input The input stream representing the dssDocument to be created.
     * @return
     * @throws SAXException
     * @throws IOException
     */
    public static Document buildDOM(InputStream input) throws SAXException, IOException, ParserConfigurationException {
        ensureDocumentBuilder();

        final Document rootElement = documentBuilder.parse(input);
        return rootElement;
    }

    /**
     * This method returns the {@link org.w3c.dom.Document} created based on the
     * {@link eu.europa.ec.markt.dss.signature.DSSDocument}.
     *
     * @param dssDocument The DSS representation of the document from which the dssDocument is created.
     * @return
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     */
    public static Document buildDOM(final DSSDocument dssDocument) throws ParserConfigurationException, IOException, SAXException {

        final InputStream input = dssDocument.openStream();
        Document doc = null;
        try {

            doc = buildDOM(input);
        } finally {

            DSSUtils.closeQuietly(input);
        }
        return doc;
    }

    /**
     * This method write formatted {@link org.w3c.dom.Node} to the outputStream.
     *
     * @param node
     * @param out
     */
    public static void printDocument(Node node, OutputStream out) {

        try {

            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "3");

            transformer.transform(new DOMSource(node), new StreamResult(new OutputStreamWriter(out, "UTF-8")));
        } catch (Exception e) {

            // Ignore
        }
    }
}
