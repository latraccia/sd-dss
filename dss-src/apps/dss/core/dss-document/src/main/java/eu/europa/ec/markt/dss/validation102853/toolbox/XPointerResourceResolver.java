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
package eu.europa.ec.markt.dss.validation102853.toolbox;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashSet;
import java.util.Set;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 * An implementation of a resource resolver, which evaluates xpointer expressions.
 * 
 * @author wglas
 */
public class XPointerResourceResolver extends ResourceResolverSpi {

	private static Log log = LogFactory.getLog(XPointerResourceResolver.class);

	private static final String XP_OPEN = "xpointer(";

	private static final String XNS_OPEN = "xmlns(";

	private XPathFactory xPathFactory;

	private Node baseNode;

	public XPointerResourceResolver(Node baseNode) {

		this.xPathFactory = XPathFactory.newInstance();
		this.baseNode = baseNode;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineCanResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public boolean engineCanResolve(Attr uri, String BaseURI) {

		String v = uri.getNodeValue();

		if (v.charAt(0) != '#')
			return false;

		String xpURI;
		try {
			xpURI = URLDecoder.decode(v, "utf-8");
		} catch (UnsupportedEncodingException e) {
			log.warn("utf-8 not a valid encoding", e);
			return false;
		}

		String parts[] = xpURI.substring(1).split("\\s");

		// plain ID reference.
		if (parts.length == 1 && !parts[0].startsWith(XNS_OPEN))
			return true;

		int i = 0;

		for (; i < parts.length - 1; ++i)
			if (!parts[i].endsWith(")") || !parts[i].startsWith(XNS_OPEN))
				return false;

		if (!parts[i].endsWith(")") || !parts[i].startsWith(XP_OPEN))
			return false;

		log.debug("xpURI=" + xpURI);
		log.debug("BaseURI=" + BaseURI);

		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.xml.security.utils.resolver.ResourceResolverSpi#engineResolve(org.w3c.dom.Attr, java.lang.String)
	 */
	@Override
	public XMLSignatureInput engineResolve(Attr uri, String BaseURI) throws ResourceResolverException {

		String v = uri.getNodeValue();

		if (v.charAt(0) != '#')
			return null;

		String xpURI;
		try {
			xpURI = URLDecoder.decode(v, "utf-8");
		} catch (UnsupportedEncodingException e) {
			log.warn("utf-8 not a valid encoding", e);
			return null;
		}

		String parts[] = xpURI.substring(1).split("\\s");

		int i = 0;

		DSigNamespaceContext nsContext = null;

		if (parts.length > 1) {
			nsContext = new DSigNamespaceContext();

			for (; i < parts.length - 1; ++i) {
				if (!parts[i].endsWith(")") || !parts[i].startsWith(XNS_OPEN))
					return null;

				String mapping = parts[i].substring(XNS_OPEN.length(), parts[i].length() - 1);

				int pos = mapping.indexOf('=');

				if (pos <= 0 || pos >= mapping.length() - 1)
					throw new ResourceResolverException("malformed namespace part of XPointer expression", uri, BaseURI);

				nsContext.addNamespace(mapping.substring(0, pos), mapping.substring(pos + 1));
			}
		}

		try {
			Node node = null;
			NodeList nodes = null;

			// plain ID reference.
			if (i == 0 && !parts[i].startsWith(XP_OPEN)) {
				node = this.baseNode.getOwnerDocument().getElementById(parts[i]);
			} else {
				if (!parts[i].endsWith(")") || !parts[i].startsWith(XP_OPEN))
					return null;

				XPath xp = this.xPathFactory.newXPath();

				if (nsContext != null)
					xp.setNamespaceContext(nsContext);

				nodes = (NodeList) xp.evaluate(parts[i].substring(XP_OPEN.length(), parts[i].length() - 1), this.baseNode,
						XPathConstants.NODESET);

				if (nodes.getLength() == 0)
					return null;
				if (nodes.getLength() == 1)
					node = nodes.item(0);
			}

			XMLSignatureInput result = null;

			if (node != null) {
				result = new XMLSignatureInput(node);
			} else if (nodes != null) {
				Set<Node> nodeSet = new HashSet<Node>(nodes.getLength());

				for (int j = 0; j < nodes.getLength(); ++j) {
					nodeSet.add(nodes.item(j));
				}

				result = new XMLSignatureInput(nodeSet);
			} else
				return null;

			result.setMIMEType("text/xml");
			result.setExcludeComments(true);
			result.setSourceURI((BaseURI != null) ? BaseURI.concat(v) : v);

			return result;

		} catch (XPathExpressionException e) {
			throw new ResourceResolverException("malformed XPath inside XPointer expression", e, uri, BaseURI);
		}
	}
}