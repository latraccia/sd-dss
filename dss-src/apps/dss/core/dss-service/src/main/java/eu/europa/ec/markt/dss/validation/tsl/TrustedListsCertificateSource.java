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

package eu.europa.ec.markt.dss.validation.tsl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.naming.ConfigurationException;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.CannotFetchDataException;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

/**
 * 
 * Certificate coming from the Trusted List
 * 
 * 
 * @version $Revision: 2910 $ - $Date: 2013-11-08 15:18:08 +0100 (ven., 08 nov. 2013) $
 */

public class TrustedListsCertificateSource implements CertificateSource {

   private static final Logger LOG = Logger.getLogger(TrustedListsCertificateSource.class.getName());

   private String lotlUrl;

   private HTTPDataLoader tslLoader;

   private Map<X500Principal, List<CertificateAndContext>> certificates;

   private Map<String, String> diagnosticInfo = new ConcurrentHashMap<String, String>();

   private boolean checkSignature = true;

   private String lotlCertificate;

   // prefix of a resource to be found on the classpath - Spring notation
   private static final String CP = "classpath://";
   private static final String FILE = "file://";

   /**
    * The default constructor for TrustedListsCertificateSource.
    */
   public TrustedListsCertificateSource() {

      Security.addProvider(new BouncyCastleProvider());
   }

   /**
    * Add a service entry (current or history) to the list of CertificateAndContext
    * 
    * @param cert
    * @param s
    * @param provider
    */
   private void addCertificate(X509Certificate cert, AbstractTrustService s, TrustServiceProvider provider, boolean wellsigned) {

      List<CertificateAndContext> list = certificates.get(cert.getSubjectX500Principal());
      if (list == null) {
         list = Collections.synchronizedList(new ArrayList<CertificateAndContext>());
         certificates.put(cert.getSubjectX500Principal(), list);
      }

      if (LOG.isLoggable(Level.INFO)) {

         LOG.info("Certificate added from TL: " + CertificateIdentifier.getId(cert));
      }

      CertificateAndContext certAndCtx = new CertificateAndContext(cert);
      certAndCtx.setCertificateSource(CertificateSourceType.TRUSTED_LIST);

      try {
         ServiceInfo info = s.createServiceInfo();
         info.setCurrentStatus(s.getCurrentServiceInfo().getStatus());
         info.setCurrentStatusStartingDate(s.getCurrentServiceInfo().getStatusStartDate());
         info.setServiceName(s.getServiceName());
         info.setStatusAtReferenceTime(s.getStatus());
         info.setStatusStartingDateAtReferenceTime(s.getStatusStartDate());
         info.setStatusEndingDateAtReferenceTime(s.getStatusEndDate());
         info.setTspElectronicAddress(provider.getElectronicAddress());
         info.setTspName(provider.getName());
         info.setTspPostalAddress(provider.getPostalAddress());
         info.setTspTradeName(provider.getTradeName());
         info.setType(s.getType());
         info.setTlWellSigned(wellsigned);
         certAndCtx.setContext(info);
         list.add(certAndCtx);
      } catch (NotETSICompliantException ex) {

         LOG.log(Level.SEVERE, "The entry for " + s.getServiceName() + " don't respect ESTI specification " + ex.getMessage());
      }
   }

   private XPathExpression createXPathExpression(String xpathString) {

      /* XPath */
      XPathFactory factory = XPathFactory.newInstance();
      XPath xpath = factory.newXPath();
      // TODO by meyerfr: why not use a static context implementation instead of on-the-fly generation?
      xpath.setNamespaceContext(new NamespaceContext() {

         @Override
         public String getNamespaceURI(String prefix) {

            if ("ds".equals(prefix)) {
               return XMLSignature.XMLNS;
            } else if ("etsi".equals(prefix)) {
               return "http://uri.etsi.org/01903/v1.1.1#";
            } else if ("xades".equals(prefix)) {
               return "http://uri.etsi.org/01903/v1.3.2#";
            } else if ("xades141".equals(prefix)) {
               return "http://uri.etsi.org/01903/v1.4.1#";
            }
            throw new RuntimeException("Prefix not recognized : " + prefix);
         }

         @Override
         public String getPrefix(String namespaceURI) {

            throw new RuntimeException();
         }

         @Override
         public Iterator<?> getPrefixes(String namespaceURI) {

            throw new RuntimeException();
         }
      });

      try {
         return xpath.compile(xpathString);
      } catch (XPathExpressionException ex) {
         throw new RuntimeException(ex);
      }

   }

   @Override
   public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {

      if (LOG.isLoggable(Level.FINE)) LOG.log(Level.FINE, "Looking for {0} in {1}", new Object[] { subjectName, certificates.values() });
      return certificates.get(subjectName);
   }

   /**
    * 
    * @return
    */
   public List<CertificateAndContext> getCertificateList() {

      List<CertificateAndContext> certs = new ArrayList<CertificateAndContext>();
      for (List<CertificateAndContext> list : certificates.values()) {
         for (CertificateAndContext c : list) {
            certs.add(c);
         }
      }
      return certs;
   }

   /**
    * @return the certificates
    */
   public Map<X500Principal, List<CertificateAndContext>> getCertificates() {

      return certificates;
   }

   /**
    * @return the diagnosticInfo
    */
   public Map<String, String> getDiagnosticInfo() {

      // TODO by meyerfr: is it safe to expose the modifiable class attribute?
      return diagnosticInfo;
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

   /**
    * Gets the LOTL certificate as an input stream
    * 
    * @return the input stream
    * @throws IOException
    */
   private InputStream getLotlCertificateInputStream() throws IOException {

      InputStream is;

      if (lotlCertificate.toLowerCase().startsWith(CP)) {
         is = TrustedListsCertificateSource.class.getClassLoader().getResourceAsStream(lotlCertificate.substring(CP.length()));
      } else if (lotlCertificate.toLowerCase().startsWith(FILE)) {

         URL url = new File(lotlCertificate.substring(FILE.length())).toURI().toURL();
         is = url.openStream();
      } else {

         // TODO maybe this should work through a proxy?
         URL url = new URL(lotlCertificate);
         is = url.openStream();
      }
      return is;
   }

   /**
    * Load a trusted list for the specified URL
    * 
    * @param url
    * @param signerIdentity
    * @return
    * @throws IOException
    */
   private TrustStatusList getTrustStatusList(String url, X509Certificate signerIdentity) throws IOException, CannotFetchDataException {

      try {

         InputStream input = tslLoader.get(url);

         // solution to manage (known) zipped data
         // by convention a zipped tsl has a url with that suffix
         if (url.toLowerCase().endsWith(".zip")) {
            LOG.warning("probably found a zipped TSL: " + url);
            ZipInputStream zis = null;
            try {
               zis = new ZipInputStream(input);
               LOG.fine("trying to determine the correct entry");
               while (true) {
                  final ZipEntry entry = zis.getNextEntry();
                  if (entry == null) {
                     break;
                  }
                  // by convention, the first file with xml suffix is used
                  if (entry.getName().toLowerCase().endsWith(".xml")) {
                     LOG.fine("found: " + entry.getName());
                     // if found, just use the zip stream as input.
                     // only the relevant part of the underlying stream will be used
                     // and automatically closed.
                     input = zis;
                     break;
                  }
               }
            } catch (Exception e) {
               LOG.log(Level.WARNING, "the data in assumed zip format could not be read, will continue with xml", e);
            } finally {
               // if the xml was inspected but not found
               if (zis != null && input != zis) {
                  // close the zip stream (closes also the underlying one)
                  zis.close();
                  // re-fetch the original stream
                  LOG.fine("no matching entry found - going to refetch the url");
                  input = tslLoader.get(url);
               }
            }
         }

         // TODO by meyerfr: manage closing the stream in case of exception
         DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
         dbf.setNamespaceAware(true);
         DocumentBuilder db = dbf.newDocumentBuilder();
         Document doc = db.parse(input);
         input.close();

         boolean coreValidity = false;

         if (signerIdentity != null && checkSignature) {
            NodeList signatureNodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

            if (signatureNodeList.getLength() == 0) {
               throw new NotETSICompliantException(NotETSICompliantException.MSG.TSL_NOT_SIGNED);
            }
            if (signatureNodeList.getLength() > 1) {
               throw new NotETSICompliantException(NotETSICompliantException.MSG.MORE_THAN_ONE_SIGNATURE);
            }

            final Element signatureEl = (Element) signatureNodeList.item(0);

            try {
               DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(signerIdentity.getPublicKey()), signatureEl);
               // TODO by meyerfr: why not use a static dereferencer implementation instead of on-the-fly
               // generation?
               valContext.setURIDereferencer(new URIDereferencer() {

                  @Override
                  public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {

                     try {
                        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
                        return fac.getURIDereferencer().dereference(uriReference, context);
                     } catch (URIReferenceException ex) {
                        if (uriReference.getType().equals("http://uri.etsi.org/01903/v1.1.1#SignedProperties")) {
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
                        throw ex;
                     }
                  }
               });
               XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
               XMLSignature signature = factory.unmarshalXMLSignature(valContext);
               coreValidity = signature.validate(valContext);

               LOG.fine("TSL " + url + " well signed");
            } catch (XMLSignatureException ex) {
               throw new RuntimeException("Problem validating signature of " + url, ex);
            } catch (MarshalException e) {
               throw new RuntimeException("Problem validating signature of " + url, e);
            }

         }

         TrustStatusList tsl = TrustServiceListFactory.newInstance(doc);
         tsl.setWellSigned(coreValidity);
         return tsl;
      } catch (ParserConfigurationException ex) {
         LOG.log(Level.SEVERE, "Error in TSL parsing " + ex.getMessage(), ex);
         throw new RuntimeException(ex);
      } catch (SAXException e) {
         throw new NotETSICompliantException(NotETSICompliantException.MSG.NOT_A_VALID_XML);
      }
   }

    private static class FutureResult{
        public final PointerToOtherTSL pointer;
        public final TrustStatusList trustStatusList;
        public final boolean wellSigned;

        private FutureResult(PointerToOtherTSL pointer, TrustStatusList trustStatusList, boolean wellSigned) {
            this.pointer = pointer;
            this.trustStatusList = trustStatusList;
            this.wellSigned = wellSigned;
        }
    }

   /**
    * Load the certificates contained in all the TSL referenced by the LOTL
    * 
    * @throws IOException
    */
   public void init() throws IOException, ConfigurationException, CannotFetchDataException {

      certificates = new ConcurrentHashMap<X500Principal, List<CertificateAndContext>>();

      X509Certificate lotlCert = null;
      if (checkSignature) {

         if (lotlCertificate == null) {
            throw new ConfigurationException("The LOTL certificate property must contain a reference to the LOTL signer's certificate.");
         }

         CertificateFactory factory = null;
         try {
            factory = CertificateFactory.getInstance("X509");
         } catch (CertificateException e) {
            throw new ConfigurationException("Platform does not support X509 certificate");
         }

         InputStream is = null;
         try {
            is = getLotlCertificateInputStream();
            lotlCert = (X509Certificate) factory.generateCertificate(is);
         } catch (CertificateException e) {
            diagnosticInfo.put(lotlUrl, "Cannot read certificate");
            throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
         } finally {
            DSSUtils.closeQuietly(is);
         }
      }

      LOG.log(Level.INFO, "Loading LOTL from " + lotlUrl);
      TrustStatusList lotl = null;
      try {
         lotl = getTrustStatusList(lotlUrl, lotlCert);
      } catch (NotETSICompliantException e) {
         LOG.severe("TSL not compliant with ETSI " + e.getMessage());
      }
      diagnosticInfo.put(lotlUrl, "Loaded " + new Date().toString());

       List<Callable<FutureResult>> callables = new ArrayList<Callable<FutureResult>>();
       for (final PointerToOtherTSL p : lotl.getOtherTSLPointers()) {
           final Callable<FutureResult> callable = new Callable<FutureResult>() {
               @Override
               public FutureResult call() {
                   try {

                       diagnosticInfo.put(p.getTslLocation(), "Loading");
                       X509Certificate cert = p.getDigitalId();
                       boolean wellSigned = true;
                       if (cert == null) {
                           LOG.severe("The certificate with which the list of '" + p
                                 .getTerritory() + "' was signed is absent.");
                           wellSigned = false;
                       }
                       LOG.info(
                             "Loading TrustStatusList fo '" + p.getTerritory() + "' from url= " + p.getTslLocation());
                       TrustStatusList countryTSL = getTrustStatusList(p.getTslLocation(), cert);
                       return new FutureResult(p, countryTSL, wellSigned);
                   } catch (CannotFetchDataException e) {
                       LOG.log(Level.SEVERE, "Error when reading TSL", e);
                       diagnosticInfo.put(p.getTslLocation(), getStackTrace(e));
                   } catch (CertificateException e) {
                       LOG.log(Level.SEVERE, "Cannot read certificate from pointer to " + p.getTerritory(), e);
                       diagnosticInfo.put(p.getTslLocation(), getStackTrace(e));
                   } catch (IOException e) {
                       LOG.log(Level.SEVERE, "Error when reading TSL", e);
                       diagnosticInfo.put(p.getTslLocation(), getStackTrace(e));
                   } catch (NotETSICompliantException e) {
                       LOG.severe("TSL not compliant with ETSI " + e.toString());
                       diagnosticInfo.put(p.getTslLocation(), getStackTrace(e));
                   } catch (RuntimeException e) {
                       LOG.severe("TSL not compliant with ETSI (RuntimeException): " + e.toString());
                       diagnosticInfo.put(p.getTslLocation(), getStackTrace(e));
                   }
                   return null;
               }
           };
           callables.add(callable);
       }
       try {
           final ExecutorService executorService = Executors.newFixedThreadPool(lotl.getOtherTSLPointers().size());
           final List<Future<FutureResult>> futureList = executorService.invokeAll(callables);

           for (final Future<FutureResult> future : futureList) {
               final FutureResult futureResult;
               futureResult = future.get();
               if (futureResult != null) {
                   loadAllCertificatesFromOneTSL(futureResult.trustStatusList, futureResult.wellSigned);
                   diagnosticInfo.put(futureResult.pointer.getTslLocation(), "Loaded " + new Date().toString());
               }
           }
           executorService.shutdown();
            LOG.info("Done loading TLs from " + lotlUrl);
       } catch (InterruptedException e) {
           LOG.log(Level.SEVERE, "TSL load error: " + e.toString(), e);
       } catch (ExecutionException e) {
           LOG.log(Level.SEVERE, "TSL load error: " + e.toString(), e);
       }

   }

    private String getStackTrace(Throwable e) {
        StringWriter w = new StringWriter();
        e.printStackTrace(new PrintWriter(w));
        return w.toString();
    }

    /**
    * Add all the service entry (current and history) of all the providers of the trusted list to the list of
    * CertificateSource
    * 
    * @param tsl
    */
   private void loadAllCertificatesFromOneTSL(TrustStatusList tsl, boolean wellSigned) {

      for (TrustServiceProvider p : tsl.getTrustServicesProvider()) {
         for (AbstractTrustService s : p.getTrustServiceList()) {
            for (X509Certificate c : s.getDigitalIdentity()) {
               addCertificate(c, s, p, wellSigned);
            }
         }
      }
   }

   /**
    * Define if we must check the TL signature
    * 
    * @param checkSignature the checkSignature to set
    */
   public void setCheckSignature(boolean checkSignature) {

      this.checkSignature = checkSignature;
   }

   /**
    * @param lotlCertificate the lotlCertificate to set
    */
   public void setLotlCertificate(String lotlCertificate) {

      this.lotlCertificate = lotlCertificate;
   }

   /**
    * @param tslLoader the tslLoader to set
    */
   public void setTslLoader(HTTPDataLoader tslLoader) {

      this.tslLoader = tslLoader;
   }

    /**
     * Define the URL of the LOTL
     *
     * @param lotlUrl the lotlUrl to set
     */
    public void setLotlUrl(String lotlUrl) {

        this.lotlUrl = lotlUrl;
    }

}
