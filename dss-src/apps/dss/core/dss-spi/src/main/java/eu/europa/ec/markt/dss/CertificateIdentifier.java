package eu.europa.ec.markt.dss;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * This class is used to obtain a unique DSS certificate's id. It is very helpful to follow the relationships between
 * certificates, CRLs, OCSPs and signatures. This DSS unique id is a simple integer number.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public final class CertificateIdentifier {

   /**
    * This is the id which is given to a new certificate.
    */
   private static int nextCertificateIdentifier = 1;

   /**
    * This {@link LinkedHashMap} represents the association between the certificate unique identifier (certificate's
    * issuer distinguished name + "|" + certificate's serial number) and the DSS certificate's id.
    */
   private static LinkedHashMap<String, Integer> ids = new LinkedHashMap<String, Integer>();

   /**
    * This method returns the DSS certificate's id based on the certificate's key: ( issuer distinguished name + "|" +
    * serial number). If the certificate is not yet stored it is added to the <code>ids</code>.
    * 
    * @param key
    * @return
    */
   private static int add(String key) {

      Integer id = ids.get(key);
      if (id == null) {

         id = nextCertificateIdentifier;
         ids.put(key, id);
         nextCertificateIdentifier++;
      }
      return id;
   }

   @Deprecated
   public static int getId(CertificateAndContext certiticateAndContext) {
      if (certiticateAndContext == null) {
         return 0;
      }
      return getId(certiticateAndContext.getCertificate());
   }

   /**
    * This method returns the DSS certificate's id for a given {@link CertificateToken}.
    * 
    * @param certToken
    * @return
    */
   public static int getId(CertificateToken certToken) {

      if (certToken == null) {
         return 0;
      }
      return getId(certToken.getCertificate());
   }

   /**
    * Return the DSS certificate's unique id for a given {@link X509Certificate}. If the <code>cert</code> parameter is
    * null 0 is returned.
    * 
    * @param cert
    * @return
    */
   public static int getId(X509Certificate cert) {
      if (cert == null) {
            throw new DSSException("The certificate cannot be null!");
      }
      String certKey = getKey(cert);
      Integer id = ids.get(certKey);
      if (id == null) {

         id = add(certKey);
      }
      return id;
   }

   /**
    * Return the DSS certificate's unique id based on issuerDN and serial number. If the <code>cert</code> parameter is
    * null null is returned.
    * 
    * @param cert
    * @return
    */
   public static String getIdAsString(X509Certificate cert) {
      if (cert == null) {
         return null;
      }
      Integer id = getId(cert);
      return "[" + id + "]";
   }

   /**
    * This method returns the unique identifier of a given {@link X509Certificate}. This identifier is used to obtain
    * the DSS certificate's unique id.
    * 
    * @param cert
    * @return
    */
   private static String getKey(X509Certificate cert) {

      return cert.getIssuerX500Principal().getName(X500Principal.CANONICAL) + "|" + cert.getSerialNumber().toString();
   }

   /**
    * This method reset the list of certificates.
    * 
    */
   public static void clear() {
      ids.clear();
      nextCertificateIdentifier = 1;
   }

   /**
    * Returns the text representation of all certificates and their internal DSS number. The text is indented with the
    * given <code>indentStr</code> string.
    * 
    * @param indentStr
    * @return
    */
   public static String toString(String indentStr) {

      StringBuilder sb = new StringBuilder();

      sb.append(indentStr).append("List of certificates:\n");
      for (Entry<String, Integer> entry : ids.entrySet()) {

         Integer id = entry.getValue();
         String key = entry.getKey();
         sb.append(indentStr).append(String.format("[%s] : %s\n", id, key));
      }
      return sb.toString();
   }

   /**
    * Returns the text representation of all certificates and their internal DSS number.
    * 
    * @return
    */
   public static String print() {
      return toString("");
   }
}
