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

package eu.europa.ec.markt.dss.validation102853.engine.function;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.NamespaceContextMap;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ValidationResourceManager;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;

/**
 * This class encapsulates an org.w3c.dom.Document. Its integrates the ability to execute XPath queries on XML
 * documents.
 *
 * @author bielecro
 */
public class XmlDom {

    private static final XPathFactory factory = XPathFactory.newInstance();

    private static final NamespaceContext nsContext;

    private static final Map<String, String> namespaces;

    static {

        namespaces = new HashMap<String, String>();
        namespaces.put("dss", ValidationResourceManager.DIAGNOSTIC_DATA_NAMESPACE);
        nsContext = new NamespaceContextMap(namespaces);
    }

    Element rootElement;

    String nameSpace;

    public XmlDom(Document document) {

        this.rootElement = document.getDocumentElement();
        nameSpace = rootElement.getNamespaceURI();
    }

    public XmlDom(Element element) {

        this.rootElement = element;
    }

    private static XPathExpression createXPathExpression(String xpathString) {

        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(nsContext);
        try {

            XPathExpression expr = xpath.compile(xpathString);
            return expr;
        } catch (XPathExpressionException ex) {

            throw new RuntimeException(ex);
        }
    }

    private static NodeList getNodeList(Node xmlNode, String xpathString) {

        try {

            XPathExpression expr = createXPathExpression(xpathString);
            return (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {

            throw new RuntimeException(e);
        }
    }

    /**
     * The list of elements corresponding the given XPath query and parameters.
     *
     * @param xPath
     * @param params
     * @return
     */
    public List<XmlDom> getElements(String xPath, final Object... params) {

        try {

            String xPath_ = format(xPath, params);

            NodeList nodeList = getNodeList(rootElement, xPath_);
            List<XmlDom> list = new ArrayList<XmlDom>();
            for (int ii = 0; ii < nodeList.getLength(); ii++) {

                Node node = nodeList.item(ii);
                if (node != null && node.getNodeType() == Node.ELEMENT_NODE) {

                    list.add(new XmlDom((Element) node));
                }
            }
            return list;
        } catch (Exception e) {

            String message = "XPath error: '" + xPath + "'.";
            throw new DSSException(message, e);
        }
    }

    public XmlDom getElement(final String xPath, final Object... params) {

        try {

            String xPath_ = format(xPath, params);

            NodeList nodeList = getNodeList(rootElement, xPath_);
            for (int ii = 0; ii < nodeList.getLength(); ii++) {

                Node node = nodeList.item(ii);
                if (node != null && node.getNodeType() == Node.ELEMENT_NODE) {

                    return new XmlDom((Element) node);
                }
            }
            return null;
        } catch (Exception e) {

            String message = "XPath error: '" + xPath + "'.";
            throw new DSSException(message, e);
        }
    }

    /**
     * @param xPath
     * @param params
     * @return
     */
    private static String format(final String xPath, final Object... params) {

        String formattedXPath = null;
        if (params.length > 0) {

            formattedXPath = String.format(xPath, params);
        } else {

            formattedXPath = xPath;
        }
        formattedXPath = addNamespacePrefix(formattedXPath);
        return formattedXPath;
    }

    private static String addNamespacePrefix(String formatedXPath) {

        if (formatedXPath.startsWith("/dss:") || formatedXPath.startsWith("./dss:")) {

            // Already formated.
            return formatedXPath;
        }
        StringTokenizer tokenizer = new StringTokenizer(formatedXPath, "/");

        StringBuilder stringBuilder = new StringBuilder();

        while (tokenizer.hasMoreTokens()) {

            String token = tokenizer.nextToken();

            final boolean isDot = ".".equals(token);
            final boolean isCount = "count(".equals(token);
            final boolean isDoubleDot = "..".equals(token);
            final boolean isAt = token.startsWith("@");
            final boolean isText = token.equals("text()");
            final String slash = isDot || isCount ? "" : "/";
            String prefix = isDot || isCount || isDoubleDot || isAt || isText ? "" : "dss:";

            stringBuilder.append(slash).append(prefix).append(token);
        }
        // System.out.println("");
        // System.out.println("--> " + formatedXPath);
        // System.out.println("--> " + stringBuilder.toString());
        return stringBuilder.toString();
    }

    public String getValue(final String xPath, final Object... params) {

        String xPath_ = format(xPath, params);

        NodeList nodeList = getNodeList(rootElement, xPath_);
        if (nodeList.getLength() == 1) {

            Node node = nodeList.item(0);
            if (node.getNodeType() != Node.ELEMENT_NODE) {

                String value = nodeList.item(0).getTextContent();
                return value.trim();
            }
        }
        return "";
    }

    public int getIntValue(final String xPath, final Object... params) {

        String value = getValue(xPath, params);
        try {

            return Integer.parseInt(value);
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    public long getLongValue(final String xPath, final Object... params) {

        String value = getValue(xPath, params);
        try {

            value = value.trim();
            return Long.parseLong(value);
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    public boolean getBoolValue(final String xPath, final Object... params) {

        String value = getValue(xPath, params);
        if (value.equals("true")) {
            return true;

        } else if (value.isEmpty() || value.equals("false")) {

            return false;
        }
        throw new DSSException("Expected values are: true, false and not '" + value + "'.");
    }

    public long getCountValue(final String xPath, final Object... params) {

        String xpathString = format(xPath, params);
        try {

            XPathExpression xPathExpression = createXPathExpression(xpathString);
            Double number = (Double) xPathExpression.evaluate(rootElement, XPathConstants.NUMBER);
            return number.intValue();
        } catch (XPathExpressionException e) {

            throw new RuntimeException(e);
        }
    }

    public boolean exists(final String xPath, final Object... params) {

        XmlDom element = getElement(xPath, params);
        return element != null;
    }

    public Date getTimeValue(final String xPath, final Object... params) {

        String value = getValue(xPath, params);
        return RuleUtils.parseDate(value);
    }

    public Date getTimeValueOrNull(final String xPath, final Object... params) {

        String value = getValue(xPath, params);
        if (value.isEmpty()) {
            return null;
        }
        return RuleUtils.parseDate(value);
    }

    public String getText() {

        try {
            if (rootElement != null) {

                return rootElement.getTextContent().trim();
            }
        } catch (Exception e) {
        }
        return null;
    }

    /**
     * The name of this node, depending on its type;
     *
     * @return
     */
    public String getName() {

        return rootElement.getNodeName();
    }

    /**
     * Retrieves an attribute value by name.
     *
     * @param attributeName
     * @return
     */
    public String getAttribute(String attributeName) {

        return rootElement.getAttribute(attributeName);
    }

    /**
     * Converts the list of <code>XmlDom</code> to list of <code>String</code>. The children of the node are not taken
     * into account.
     *
     * @param xmlDomList
     * @return
     */
    public static List<String> convertToStringList(List<XmlDom> xmlDomList) {

        List<String> stringList = new ArrayList<String>();
        for (XmlDom xmlDom : xmlDomList) {

            stringList.add(xmlDom.getText());
        }
        return stringList;
    }

    @Override
    public String toString() {

        try {
            if (rootElement != null) {

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DSSXMLUtils.printDocument(rootElement, baos);
                return new String(baos.toByteArray());
            }
        } catch (Exception e) {
        }
        return super.toString();
    }

    public Element getRootElement() {
        return rootElement;
    }
}
