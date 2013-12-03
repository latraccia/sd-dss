/*
 * eID TSL Project.
 * Copyright (C) 2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package eu.europa.ec.markt.dss.report;

import eu.europa.ec.markt.tsl.jaxb.ecc.CriteriaListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationsType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifiersType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.ec.markt.tsl.jaxb.tsl.PostalAddressType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifierType;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.openssl.PEMWriter;
import org.w3c.dom.Element;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.HeaderFooter;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

public class Tsl2PdfExporter {

   private static final Log LOG = LogFactory.getLog(Tsl2PdfExporter.class);

   public Tsl2PdfExporter() {
      initializeFontResources();
      title0Font = FontFactory.getFont("DejaVuSerifCondensed-Bold", BaseFont.IDENTITY_H, true, 30, Font.BOLD);
      title1Font = FontFactory.getFont("DejaVuSerifCondensed-BoldItalic", BaseFont.IDENTITY_H, true, 16, Font.BOLD | Font.ITALIC);
      title2Font = FontFactory.getFont("DejaVuSerifCondensed-BoldItalic", BaseFont.IDENTITY_H, true, 16, Font.BOLD | Font.ITALIC);
      title3Font = FontFactory.getFont("DejaVuSerifCondensed-Italic", BaseFont.IDENTITY_H, true, 16, Font.ITALIC);
      title4Font = FontFactory.getFont("DejaVuSerifCondensed-Italic", BaseFont.IDENTITY_H, true, 12, Font.BOLD);
      labelFont = FontFactory.getFont("DejaVuSerifCondensed-Italic", BaseFont.IDENTITY_H, true, 11, Font.ITALIC);
      valueFont = FontFactory.getFont("DejaVuSerifCondensed", BaseFont.IDENTITY_H, true, 11, Font.NORMAL);
      monoFont = FontFactory.getFont("DejaVuSansMono", BaseFont.IDENTITY_H, true, 5, Font.NORMAL);
      headerFooterFont = FontFactory.getFont("DejaVuSerifCondensed", BaseFont.IDENTITY_H, true, 10, Font.NORMAL);
   }

   private static void initializeFontResources() {
      try {
         final File tmpDir = createTempDirectory();
         loadFont(tmpDir, "DejaVuSerifCondensed-Bold");
         loadFont(tmpDir, "DejaVuSerifCondensed-BoldItalic");
         loadFont(tmpDir, "DejaVuSerifCondensed-Italic");
         loadFont(tmpDir, "DejaVuSerifCondensed");
         loadFont(tmpDir, "DejaVuSansMono");
         FontFactory.registerDirectory(tmpDir.getAbsolutePath());
      } catch (Exception e) {
         throw new RuntimeException("when initializing fonts", e);
      }
   }

   private static void loadFont(final File dir, final String name) {
      final String fontBase = "/org/dejavu/font/";
      final File file = new File(dir, name + ".ttf");
      final InputStream ttfStream = Tsl2PdfExporter.class.getResourceAsStream(fontBase + name + ".ttf");
      try {
         final OutputStream fileStream = new FileOutputStream(file);
         try {
            IOUtils.copy(ttfStream, fileStream);
         } finally {
            DSSUtils.closeQuietly(fileStream);
         }
      } catch (IOException e) {
         throw new RuntimeException("error initializing font", e);
      } finally {
         DSSUtils.closeQuietly(ttfStream);
      }
      file.deleteOnExit();
   }

   private static final int BORDER = 0;

   protected final Font title0Font;
   protected final Font title1Font;
   protected final Font title2Font;
   protected final Font title3Font;
   protected final Font title4Font;
   protected final Font labelFont;
   protected final Font valueFont;
   protected final Font monoFont;
   protected final Font headerFooterFont;

   /**
    * Produce a human readable export of the given tsl to the given file.
    * 
    * @param tsl the TrustServiceList to export
    * @param pdfFile the file to generate
    * @return
    * @throws IOException
    */
   public void humanReadableExport(final TrustServiceList tsl, final File pdfFile) {
      Document document = new Document();
      OutputStream outputStream;
      try {
         outputStream = new FileOutputStream(pdfFile);
      } catch (FileNotFoundException e) {
         throw new RuntimeException("file not found: " + pdfFile.getAbsolutePath(), e);
      }
      try {
         final PdfWriter pdfWriter = PdfWriter.getInstance(document, outputStream);
         pdfWriter.setPDFXConformance(PdfWriter.PDFA1B);

         // title
         final EUCountry country = EUCountry.valueOf(tsl.getSchemeTerritory());
         final String title = country.getShortSrcLangName() + " (" + country.getShortEnglishName() + "): Trusted List";

         Phrase footerPhrase = new Phrase("PDF document generated on " + new Date().toString() + ", page ", headerFooterFont);
         HeaderFooter footer = new HeaderFooter(footerPhrase, true);
         document.setFooter(footer);

         Phrase headerPhrase = new Phrase(title, headerFooterFont);
         HeaderFooter header = new HeaderFooter(headerPhrase, false);
         document.setHeader(header);

         document.open();
         addTitle(title, title0Font, Paragraph.ALIGN_CENTER, 0, 20, document);

         addLongItem("Scheme name", tsl.getSchemeName(), document);
         addLongItem("Legal Notice", tsl.getLegalNotice(), document);

         // information table
         PdfPTable informationTable = createInfoTable();
         addItemRow("Scheme territory", tsl.getSchemeTerritory(), informationTable);
         addItemRow("Scheme status determination approach", substringAfter(tsl.getStatusDeterminationApproach(), "StatusDetn/"), informationTable);

         final List<String> schemeTypes = new ArrayList<String>();
         for (final String schemeType : tsl.getSchemeTypes()) {
            schemeTypes.add(schemeType);
         }
         addItemRow("Scheme type community rules", schemeTypes, informationTable);

         addItemRow("Issue date", tsl.getListIssueDateTime().toString(), informationTable);
         addItemRow("Next update", tsl.getNextUpdate().toString(), informationTable);
         addItemRow("Historical information period", tsl.getHistoricalInformationPeriod().toString() + " days", informationTable);
         addItemRow("Sequence number", tsl.getSequenceNumber().toString(), informationTable);
         addItemRow("Scheme information URIs", tsl.getSchemeInformationUris(), informationTable);

         document.add(informationTable);

         addTitle("Scheme Operator", title1Font, Paragraph.ALIGN_CENTER, 0, 10, document);

         informationTable = createInfoTable();
         addItemRow("Scheme operator name", tsl.getSchemeOperatorName(), informationTable);
         PostalAddressType schemeOperatorPostalAddress = tsl.getSchemeOperatorPostalAddress(Locale.ENGLISH);
         addItemRow("Scheme operator street address", schemeOperatorPostalAddress.getStreetAddress(), informationTable);
         addItemRow("Scheme operator postal code", schemeOperatorPostalAddress.getPostalCode(), informationTable);
         addItemRow("Scheme operator locality", schemeOperatorPostalAddress.getLocality(), informationTable);
         addItemRow("Scheme operator state", schemeOperatorPostalAddress.getStateOrProvince(), informationTable);
         addItemRow("Scheme operator country", schemeOperatorPostalAddress.getCountryName(), informationTable);

         List<String> schemeOperatorElectronicAddressess = tsl.getSchemeOperatorElectronicAddresses();
         addItemRow("Scheme operator contact", schemeOperatorElectronicAddressess, informationTable);
         document.add(informationTable);

         addTitle("Trust Service Providers", title1Font, Paragraph.ALIGN_CENTER, 10, 2, document);

         List<TrustServiceProvider> trustServiceProviders = tsl.getTrustServiceProviders();
         for (TrustServiceProvider trustServiceProvider : trustServiceProviders) {
            addTitle(trustServiceProvider.getName(), title1Font, Paragraph.ALIGN_LEFT, 10, 2, document);

            PdfPTable providerTable = createInfoTable();
            addItemRow("Service provider trade name", trustServiceProvider.getTradeName(), providerTable);
            addItemRow("Information URI", trustServiceProvider.getInformationUris(), providerTable);
            PostalAddressType postalAddress = trustServiceProvider.getPostalAddress();
            addItemRow("Service provider street address", postalAddress.getStreetAddress(), providerTable);
            addItemRow("Service provider postal code", postalAddress.getPostalCode(), providerTable);
            addItemRow("Service provider locality", postalAddress.getLocality(), providerTable);
            addItemRow("Service provider state", postalAddress.getStateOrProvince(), providerTable);
            addItemRow("Service provider country", postalAddress.getCountryName(), providerTable);
            document.add(providerTable);

            List<TrustService> trustServices = trustServiceProvider.getTrustServices();
            for (TrustService trustService : trustServices) {
               addTitle(trustService.getName(), title2Font, Paragraph.ALIGN_LEFT, 10, 2, document);
               PdfPTable serviceTable = createInfoTable();
               addItemRow("Type", substringAfter(trustService.getType(), "Svctype/"), serviceTable);
               addItemRow("Status", substringAfter(trustService.getStatus(), "Svcstatus/"), serviceTable);
               addItemRow("Status starting time", trustService.getStatusStartingTime().toString(), serviceTable);
               document.add(serviceTable);

               addTitle("Service digital identity (X509)", title3Font, Paragraph.ALIGN_LEFT, 2, 0, document);
               final X509Certificate certificate = trustService.getServiceDigitalIdentity();
               final PdfPTable serviceIdentityTable = createInfoTable();
               addItemRow("Version", Integer.toString(certificate.getVersion()), serviceIdentityTable);
               addItemRow("Serial number", certificate.getSerialNumber().toString(), serviceIdentityTable);
               addItemRow("Signature algorithm", certificate.getSigAlgName(), serviceIdentityTable);
               addItemRow("Issuer", certificate.getIssuerX500Principal().toString(), serviceIdentityTable);
               addItemRow("Valid from", certificate.getNotBefore().toString(), serviceIdentityTable);
               addItemRow("Valid to", certificate.getNotAfter().toString(), serviceIdentityTable);
               addItemRow("Subject", certificate.getSubjectX500Principal().toString(), serviceIdentityTable);
               addItemRow("Public key", certificate.getPublicKey().toString(), serviceIdentityTable);
               // TODO certificate policies
               addItemRow("Subject key identifier", toHex(getSKId(certificate)), serviceIdentityTable);
               addItemRow("CRL distribution points", getCrlDistributionPoints(certificate), serviceIdentityTable);
               addItemRow("Authority key identifier", toHex(getAKId(certificate)), serviceIdentityTable);
               addItemRow("Key usage", getKeyUsage(certificate), serviceIdentityTable);
               addItemRow("Basic constraints", getBasicConstraints(certificate), serviceIdentityTable);

               byte[] encodedCertificate;
               try {
                  encodedCertificate = certificate.getEncoded();
               } catch (CertificateEncodingException e) {
                  throw new RuntimeException("cert: " + e.getMessage(), e);
               }
               addItemRow("SHA1 Thumbprint", DigestUtils.shaHex(encodedCertificate), serviceIdentityTable);
               addItemRow("SHA256 Thumbprint", DigestUtils.sha256Hex(encodedCertificate), serviceIdentityTable);
               document.add(serviceIdentityTable);

               List<ExtensionType> extensions = trustService.getExtensions();
               for (ExtensionType extension : extensions) {
                  printExtension(extension, document);
               }

               addLongMonoItem("The decoded certificate:", certificate.toString(), document);
               addLongMonoItem("The certificate in PEM format:", toPem(certificate), document);
            }
         }

         X509Certificate signerCertificate = tsl.verifySignature();
         if (null != signerCertificate) {
            Paragraph tslSignerTitle = new Paragraph("Trusted List Signer", title1Font);
            tslSignerTitle.setAlignment(Paragraph.ALIGN_CENTER);
            document.add(tslSignerTitle);

            final PdfPTable signerTable = createInfoTable();
            addItemRow("Subject", signerCertificate.getSubjectX500Principal().toString(), signerTable);
            addItemRow("Issuer", signerCertificate.getIssuerX500Principal().toString(), signerTable);
            addItemRow("Not before", signerCertificate.getNotBefore().toString(), signerTable);
            addItemRow("Not after", signerCertificate.getNotAfter().toString(), signerTable);
            addItemRow("Serial number", signerCertificate.getSerialNumber().toString(), signerTable);
            addItemRow("Version", Integer.toString(signerCertificate.getVersion()), signerTable);
            byte[] encodedPublicKey = signerCertificate.getPublicKey().getEncoded();
            addItemRow("Public key SHA1 Thumbprint", DigestUtils.shaHex(encodedPublicKey), signerTable);
            addItemRow("Public key SHA256 Thumbprint", DigestUtils.sha256Hex(encodedPublicKey), signerTable);
            document.add(signerTable);

            addLongMonoItem("The decoded certificate:", signerCertificate.toString(), document);
            addLongMonoItem("The certificate in PEM format:", toPem(signerCertificate), document);
            addLongMonoItem("The public key in PEM format:", toPem(signerCertificate.getPublicKey()), document);
         }

         document.close();
      } catch (DocumentException e) {
         throw new RuntimeException("PDF document error: " + e.getMessage(), e);
      } catch (Exception e) {
         throw new RuntimeException("Exception: " + e.getMessage(), e);
      }
   }

   private static final QName ADDITIONAL_SERVICE_INFORMATION_QNAME = new QName("http://uri.etsi.org/02231/v2#", "AdditionalServiceInformation");

   private void printExtension(ExtensionType extension, Document document) throws DocumentException {
      addTitle("Extension (critical: " + extension.isCritical() + ")", title3Font, Paragraph.ALIGN_LEFT, 0, 0, document);
      List<Object> contentList = extension.getContent();
      for (Object content : contentList) {
         LOG.debug("extension content: " + content.getClass().getName());
         if (content instanceof JAXBElement<?>) {
            JAXBElement<?> element = (JAXBElement<?>) content;
            LOG.debug("QName: " + element.getName());
            if (false == ADDITIONAL_SERVICE_INFORMATION_QNAME.equals(element.getName())) {
               continue;
            }
            addTitle("Additional service information", title4Font, Paragraph.ALIGN_LEFT, 0, 0, document);
            AdditionalServiceInformationType additionalServiceInformation = (AdditionalServiceInformationType) element.getValue();
            LOG.debug("information value: " + additionalServiceInformation.getInformationValue());
            NonEmptyMultiLangURIType multiLangUri = additionalServiceInformation.getURI();
            LOG.debug("URI : " + multiLangUri.getValue() + " (language: " + multiLangUri.getLang() + ")");
            document.add(new Paragraph(multiLangUri.getValue().substring(multiLangUri.getValue().indexOf("SvcInfoExt/") + "SvcInfoExt/".length()), this.valueFont));
         } else if (content instanceof Element) {
            addTitle("Qualifications", title4Font, Paragraph.ALIGN_LEFT, 0, 0, document);
            Element element = (Element) content;
            LOG.debug("element namespace: " + element.getNamespaceURI());
            LOG.debug("element name: " + element.getLocalName());
            if ("http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#".equals(element.getNamespaceURI()) && "Qualifications".equals(element.getLocalName())) {
               try {
                  QualificationsType qualifications = unmarshallQualifications(element);
                  List<QualificationElementType> qualificationElements = qualifications.getQualificationElement();
                  for (QualificationElementType qualificationElement : qualificationElements) {
                     QualifiersType qualifiers = qualificationElement.getQualifiers();
                     List<QualifierType> qualifierList = qualifiers.getQualifier();
                     for (QualifierType qualifier : qualifierList) {
                        document.add(new Paragraph("Qualifier: " + qualifier.getUri().substring(qualifier.getUri().indexOf("SvcInfoExt/") + "SvcInfoExt/".length()), this.valueFont));
                     }

                     CriteriaListType criteriaList = qualificationElement.getCriteriaList();
                     String description = criteriaList.getDescription();
                     if (null != description) {
                        document.add(new Paragraph("Criterial List Description", this.labelFont));
                        document.add(new Paragraph(description, this.valueFont));
                     }
                     document.add(new Paragraph("Assert: " + criteriaList.getAssert(), this.valueFont));
                     List<PoliciesListType> policySet = criteriaList.getPolicySet();
                     for (PoliciesListType policiesList : policySet) {
                        List<ObjectIdentifierType> oids = policiesList.getPolicyIdentifier();
                        for (ObjectIdentifierType oid : oids) {
                           document.add(new Paragraph("Policy OID: " + oid.getIdentifier().getValue(), this.valueFont));
                        }
                     }
                  }
               } catch (JAXBException e) {
                  LOG.error("JAXB error: " + e.getMessage(), e);
               }
            }
         }
      }
   }

   private QualificationsType unmarshallQualifications(Element element) throws JAXBException {
      JAXBContext jaxbContext = JAXBContext.newInstance(be.fedict.eid.tsl.jaxb.ecc.ObjectFactory.class);
      Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
      JAXBElement<QualificationsType> jaxbElement = (JAXBElement<QualificationsType>) unmarshaller.unmarshal(element);
      QualificationsType qualifications = jaxbElement.getValue();
      return qualifications;
   }

   private String toPem(Object object) {
      StringWriter buffer = new StringWriter();
      try {
         PEMWriter writer = new PEMWriter(buffer);
         writer.writeObject(object);
         writer.close();
         return buffer.toString();
      } catch (Exception e) {
         throw new RuntimeException("Cannot convert public key to PEM format: " + e.getMessage(), e);
      } finally {
         DSSUtils.closeQuietly(buffer);
      }
   }

   private byte[] getSKId(final X509Certificate cert) throws IOException {
      final byte[] extValue = cert.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
      if (extValue != null) {
         final ASN1OctetString str = ASN1OctetString.getInstance(new ASN1InputStream(new ByteArrayInputStream(extValue)).readObject());
         final SubjectKeyIdentifier keyId = SubjectKeyIdentifier.getInstance(new ASN1InputStream(new ByteArrayInputStream(str.getOctets())).readObject());
         return keyId.getKeyIdentifier();
      } else {
         return null;
      }
   }

   private byte[] getAKId(final X509Certificate cert) throws IOException {
      final byte[] extValue = cert.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
      if (extValue != null) {
         final DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extValue)).readObject());
         final AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
         return keyId.getKeyIdentifier();
      } else {
         return null;
      }
   }

   private static String getBasicConstraints(final X509Certificate cert) {
      final int x = cert.getBasicConstraints();
      return (x < 0) ? "CA=false" : ("CA=true; PathLen=" + ((x == Integer.MAX_VALUE) ? "unlimited" : String.valueOf(x)));
   }

   private static List<String> getCrlDistributionPoints(final X509Certificate cert) throws IOException {
      final byte[] extValue = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
      if (extValue != null) {
         final ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(extValue));
         final DERObject derObj = oAsnInStream.readObject();
         final DEROctetString dos = (DEROctetString) derObj;
         final byte[] val2 = dos.getOctets();
         final ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(val2));
         final DERObject derObj2 = oAsnInStream2.readObject();
         return getDERValue(derObj2);
      } else {
         return Collections.emptyList();
      }
   }

   @SuppressWarnings("unchecked")
   private static List<String> getDERValue(final DERObject derObj) {
      if (derObj instanceof DERSequence) {
         final List<String> ret = new LinkedList<String>();
         final DERSequence seq = (DERSequence) derObj;
         final Enumeration<DERObject> enum1 = seq.getObjects();
         while (enum1.hasMoreElements()) {
            final DERObject nestedObj = (DERObject) enum1.nextElement();
            final List<String> appo = getDERValue(nestedObj);
            if (appo != null) {
               ret.addAll(appo);
            }
         }
         return ret;
      }

      if (derObj instanceof DERTaggedObject) {
         final DERTaggedObject derTag = (DERTaggedObject) derObj;
         if (derTag.isExplicit() && !derTag.isEmpty()) {
            final DERObject nestedObj = derTag.getObject();
            return getDERValue(nestedObj);
         } else {
            final DEROctetString derOct = (DEROctetString) derTag.getObject();
            final String val = new String(derOct.getOctets());
            return Collections.singletonList(val);
         }
      }

      return null;
   }

   private static final String[] keyUsageLabels = new String[] { "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly",
            "decipherOnly" };

   private static List<String> getKeyUsage(final X509Certificate cert) {
      final boolean[] keyUsage = cert.getKeyUsage();
      if (keyUsage != null) {
         final List<String> ret = new LinkedList<String>();
         for (int i = 0; i < keyUsage.length; ++i) {
            if (keyUsage[i]) {
               if (i < keyUsageLabels.length) {
                  ret.add(keyUsageLabels[i]);
               } else {
                  ret.add(String.valueOf(i));
               }
            }
         }
         return ret;
      } else {
         return null;
      }
   }

   protected PdfPTable createInfoTable() {
      final float alpha = 0.22f;
      final PdfPTable t = new PdfPTable(new float[] { alpha, 1.0f - alpha });
      t.getDefaultCell().setBorder(BORDER);
      t.setWidthPercentage(101f);
      return t;
   }

   protected void addItemRow(final String label, final String value, final PdfPTable table) {
      if (value != null) {
         table.addCell(new Phrase(label, labelFont));
         table.addCell(new Phrase(value, valueFont));
      }
   }

   protected void addItemRow(final String label, final Iterable<String> values, final PdfPTable table) {
      if (values != null) {
         boolean nonEmpty = false;
         final PdfPCell valueCell = new PdfPCell();
         valueCell.setBorder(0);
         for (String s : values) {
            valueCell.addElement(new Paragraph(s, valueFont));
            nonEmpty = true;
         }
         if (nonEmpty) {
            table.addCell(new Phrase(label, labelFont));
            table.addCell(valueCell);
         }
      }
   }

   protected void addLongItem(final String label, final String value, final Document doc) throws DocumentException {
      doc.add(new Paragraph(label, labelFont));
      doc.add(new Paragraph(value, valueFont));
   }

   protected void addLongMonoItem(final String label, final String value, final Document doc) throws DocumentException {
      doc.add(new Paragraph(label, labelFont));
      doc.add(new Paragraph(value, monoFont));
   }

   protected void addTitle(final String titleText, final Font titleFont, final int align, final float spacingBefore, final float spacingAfter, final Document doc) throws DocumentException {
      final Paragraph titlePara = new Paragraph(titleText, titleFont);
      titlePara.setAlignment(align);
      titlePara.setSpacingBefore(spacingBefore);
      titlePara.setSpacingAfter(spacingAfter);
      doc.add(titlePara);
   }

   protected static String substringAfter(final String mainString, final String substring) {
      return mainString.substring(mainString.indexOf(substring) + substring.length());
   }

   protected static String toHex(final byte[] value) {
      return (value != null) ? Hex.encodeHexString(value) : null;
   }

   private static File createTempDirectory() throws IOException {
      final File tmpDir = File.createTempFile("eid-tsl-", ".fonts");
      tmpDir.delete();
      tmpDir.mkdir();
      tmpDir.deleteOnExit();
      return tmpDir;
   }

}
