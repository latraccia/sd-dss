/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/trunk/buildtools/src/main/resources/eclipse/dss-java-code-template.xml $
 * $Revision: 672 $
 * $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * $Author: hiedelch $
 */
package eu.europa.ec.markt.dss.validation.asic;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Validator for ASiC document
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
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
         signatureInfos.add(new XAdESSignature(signatureEl));
      }

      return signatureInfos;
   }

}
