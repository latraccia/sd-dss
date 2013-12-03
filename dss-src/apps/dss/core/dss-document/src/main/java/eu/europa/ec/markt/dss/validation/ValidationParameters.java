package eu.europa.ec.markt.dss.validation;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * 
 * This class represents a set of parameters used in validation process like signing certificate...
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ValidationParameters {

    /*
     * If the signer's certificate cannot be found in the signature it can be obtained using external sources.
     */
    private final ArrayList<X509Certificate> signingCertificate = new ArrayList<X509Certificate>();

    public X509Certificate getSigningCertificate(int index) {

        X509Certificate certificate = null;
        try {

            certificate = signingCertificate.get(index);
        } catch (IndexOutOfBoundsException e) {

            // return null ;
        }
        return certificate;
    }

    public void setSigningCertificate(X509Certificate signingCertificate) {

        this.signingCertificate.add(signingCertificate);
    }

}
