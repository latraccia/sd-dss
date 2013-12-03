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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.exception.DSSException;

public class XmlNode {

    private String name;
    private String value;
    private String nameSpace = "";

    // List<XmlAttribute> attributes = new ArrayList<XmlAttribute>();
    private HashMap<String, String> attributes = new HashMap<String, String>();

    private List<XmlNode> children = new ArrayList<XmlNode>();

    private XmlNode parentNode;

    public XmlNode(String name) {

        this(name, null);
    }

    public XmlNode(String name, String value) {

        int _pos = name.indexOf(' ');
        if (_pos != -1) {

            throw new DSSException("The node name is not correct: " + name);
        }
        this.name = name;
        this.value = value;
    }

    public void addChild(XmlNode child) {

      /* if (!children.contains(child)) */
        children.add(child);
    }

    public void addChildrenOf(XmlNode parent) {

        for (XmlNode child : parent.children) {

            children.add(child);
        }
    }

    public void addChildren(final List<XmlDom> adestInfo) {

        for (final XmlDom xmlDom : adestInfo) {

            addChild(xmlDom);
        }
    }

    public void addChild(final XmlDom child) {

        final Element element = child.rootElement;
        recursiveCopy(this, element);
    }

    public void addChildrenOf(final XmlDom parent) {

        final Element element = parent.rootElement;
        final NodeList nodes = element.getChildNodes();
        for (int ii = 0; ii < nodes.getLength(); ii++) {

            final Node node = nodes.item(ii);
            if (node.getNodeType() == Node.ELEMENT_NODE) {

                recursiveCopy(this, node);
            }
        }
    }

    /**
     * @param xmlNode the <code>XmlNode</code> to which the element is added
     * @param element the <code>Node</code> to be copied
     */
    private static void recursiveCopy(final XmlNode xmlNode, final Node element) {

        final String name = element.getNodeName();
        final XmlNode _xmlNode = new XmlNode(name);
        final NamedNodeMap attributes = element.getAttributes();
        for (int jj = 0; jj < attributes.getLength(); jj++) {

            final Node attrNode = attributes.item(jj);
            final String attrName = attrNode.getNodeName();
            if (!"xmlns".equals(attrName)) {

                _xmlNode.setAttribute(attrName, attrNode.getNodeValue());
            }
        }

        final NodeList nodes = element.getChildNodes();
        boolean hasElementNodes = false;
        for (int ii = 0; ii < nodes.getLength(); ii++) {

            final Node node = nodes.item(ii);
            if (node.getNodeType() == Node.ELEMENT_NODE) {

                hasElementNodes = true;
                recursiveCopy(_xmlNode, node);
            }
        }
        if (!hasElementNodes) {

            final String value = element.getTextContent();
            _xmlNode.setValue(value);
        }
        _xmlNode.setParent(xmlNode);
    }

    public XmlNode addChild(String childName) {

        XmlNode child = new XmlNode(childName);
        children.add(child);
        child.parentNode = this;
        return child;
    }

    public XmlNode addChild(String childName, String value) {

        XmlNode child = new XmlNode(childName, value);
        children.add(child);
        return child;
    }

    public XmlNode addFirstChild(String childName, String value) {

        XmlNode child = new XmlNode(childName, value);
        children.add(0, child);
        return child;
    }

    public XmlNode getParent() {
        return parentNode;
    }

    public void setParent(XmlNode parentNode) {

        this.parentNode = parentNode;
        if (parentNode != null) {

            parentNode.addChild(this);
        }
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getNameSpace() {
        return nameSpace;
    }

    public void setNameSpace(String nameSpace) {
        this.nameSpace = nameSpace;
    }

    public void setAttribute(String name, String value) {

        attributes.put(name, value);
    }

    private String getAttributeString() {
        StringBuilder attributeString = new StringBuilder();
        Set<Map.Entry<String, String>> entries = attributes.entrySet();
        for (Entry<String, String> entry : entries) {
            attributeString.append(" ").append(entry.getKey()).append("='").append(entry.getValue()).append("'");
        }
        return attributeString.toString();
    }

    private void writeNodes(final XmlNode node, final StringBuilder xml, final StringBuilder indent, String nameSpace) {

        for (XmlNode node_ : node.children) {

            xml.append(indent).append('<').append(node_.name);
            if (!node_.attributes.isEmpty()) {

                xml.append(node_.getAttributeString());
            }
            if (!node_.nameSpace.isEmpty()) {

                if (!nameSpace.equals(node_.nameSpace)) {

                    xml.append(' ').append(String.format("xmlns=\"%s\"", node_.nameSpace));
                    nameSpace = node_.nameSpace;
                }
            }
            xml.append('>');
            if (node_.children.size() > 0) {

                xml.append('\n');
                indent.append('\t');
                writeNodes(node_, xml, indent, nameSpace);
                indent.setLength(indent.length() - 1);
                xml.append(indent).append("</").append(node_.name).append('>').append('\n');
            } else {

                if (node_.value == null) {

                    xml.append("</").append(node_.name).append('>').append('\n');
                } else {

                    xml.append(node_.value).append("</").append(node_.name).append('>').append('\n');
                }
            }
        }
    }

    /**
     * @return
     */
    public InputStream getInputStream() {

        StringBuilder indent = new StringBuilder();
        StringBuilder xml = new StringBuilder();
        XmlNode masterNode = new XmlNode("__Master__");
        XmlNode savedParentNode = getParent();
        if (savedParentNode != null) {

            setNameSpace(savedParentNode.getNameSpace());
        }
        setParent(masterNode);
        writeNodes(masterNode, xml, indent, "");
        parentNode = savedParentNode;
        InputStream in = new ByteArrayInputStream(xml.toString().getBytes());
        return in;
    }

    @Override
    public String toString() {

        try {

            StringBuilder indent = new StringBuilder();
            StringBuilder xml = new StringBuilder();
            XmlNode masterNode = new XmlNode("__Master__", null);
            XmlNode savedParentNode = getParent();
            setParent(masterNode);
            writeNodes(masterNode, xml, indent, "");
            parentNode = savedParentNode;
            return xml.toString();
        } catch (Exception e) {

            return super.toString();
        }
    }
}
