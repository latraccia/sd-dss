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
package eu.europa.ec.markt.dss.signature.xades;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.NamespaceContext;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class NamespacePrefixMapperImpl extends NamespacePrefixMapper implements NamespaceContext {

   private static final String[] EMPTY_STRING = new String[0];

   private Map<String, String> prefixToUri = null;
   private Map<String, String> uriToPrefix = null;

   private void init() {

      prefixToUri = new HashMap<String, String>();

      prefixToUri.put("", "http://uri.etsi.org/01903/v1.3.2#");
      prefixToUri.put("ds", XMLSignature.XMLNS);
      prefixToUri.put("dsig", XMLSignature.XMLNS);
      prefixToUri.put("xades", "http://uri.etsi.org/01903/v1.3.2#");
      prefixToUri.put("xades141", "http://uri.etsi.org/01903/v1.4.1#");
      prefixToUri.put("xades122", "http://uri.etsi.org/01903/v1.2.2#");
      prefixToUri.put("xades111", "http://uri.etsi.org/01903/v1.1.1#");

      uriToPrefix = new HashMap<String, String>();

      for (String prefix : prefixToUri.keySet()) {
         uriToPrefix.put(prefixToUri.get(prefix), prefix);
      }
   }

   @Override
   public String[] getContextualNamespaceDecls() {
      return EMPTY_STRING;
   }

   @Override
   public String getNamespaceURI(String prefix) {
      if (prefixToUri == null) init();

      if (prefixToUri.containsKey(prefix)) {
         final String uri = prefixToUri.get(prefix);
         return uri;
      } else {
         return XMLConstants.NULL_NS_URI;
      }
   }

   @Override
   public String[] getPreDeclaredNamespaceUris() {
      return EMPTY_STRING;
   }

   @Override
   public String[] getPreDeclaredNamespaceUris2() {
      return null; // new String[] { "", prefixToUri.get("") };

   }

   @Override
   public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
      if (uriToPrefix == null) init();

      if (uriToPrefix.containsKey(namespaceUri)) {
         return uriToPrefix.get(namespaceUri);
      }

      return suggestion;
   }

   @Override
   public String getPrefix(String namespaceURI) {
      if (uriToPrefix == null) init();

      if (uriToPrefix.containsKey(namespaceURI)) {
         return uriToPrefix.get(namespaceURI);
      } else {
         return null;
      }
   }

   @Override
   public Iterator<String> getPrefixes(String namespaceURI) {
      if (uriToPrefix == null) init();

      List<String> prefixes = new LinkedList<String>();

      if (uriToPrefix.containsKey(namespaceURI)) {
         prefixes.add(uriToPrefix.get(namespaceURI));
      }
      return prefixes.iterator();
   }

}
