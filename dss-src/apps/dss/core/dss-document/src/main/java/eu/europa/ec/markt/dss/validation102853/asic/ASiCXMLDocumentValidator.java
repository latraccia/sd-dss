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

package eu.europa.ec.markt.dss.validation102853.asic;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

/**
 * Validator for ASiC document
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public class ASiCXMLDocumentValidator extends SignedDocumentValidator {

    Document rootElement;

    /**
     * The default constructor for ASiCXMLDocumentValidator.
     */
    public ASiCXMLDocumentValidator(DSSDocument doc, byte[] signedContent, String dataFileName) throws Exception {

        this.document = doc;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        InputStream input = this.document.openStream();
        this.rootElement = db.parse(input);

        setExternalContent(new InMemoryDocument(signedContent, dataFileName));
    }

    @Override
    public List<AdvancedSignature> getSignatures() {

        final List<AdvancedSignature> signatureInfos = new ArrayList<AdvancedSignature>();
        final NodeList signatureNodeList = this.rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        for (int i = 0; i < signatureNodeList.getLength(); i++) {

            final Element signatureEl = (Element) signatureNodeList.item(i);
            signatureInfos.add(new XAdESSignature(signatureEl, validationCertPool));
        }
        return signatureInfos;
    }

}
