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

package eu.europa.ec.markt.dss.validation.xades;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Validation of XML Signed document
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class XMLDocumentValidator extends SignedDocumentValidator {

   org.w3c.dom.Document rootElement;

   /**
    * The default constructor for XMLDocumentValidator.
    * 
    * @throws ParserConfigurationException
    * @throws IOException
    * @throws SAXException
    */
   public XMLDocumentValidator(DSSDocument document) throws ParserConfigurationException, IOException, SAXException {

      this.document = document;
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      DocumentBuilder db = dbf.newDocumentBuilder();
      InputStream input = this.document.openStream();
      this.rootElement = db.parse(input);
   }

   @Override
   public List<AdvancedSignature> getSignatures() {

      List<AdvancedSignature> signatureInfos = new ArrayList<AdvancedSignature>();
      NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
      for (int i = 0; i < signatureNodeList.getLength(); i++) {

         Element signatureEl = (Element) signatureNodeList.item(i);
         signatureInfos.add(new XAdESSignature(signatureEl));
      }
      return signatureInfos;
   }
}
