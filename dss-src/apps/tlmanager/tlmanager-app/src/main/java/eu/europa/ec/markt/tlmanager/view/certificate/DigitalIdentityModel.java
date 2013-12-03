package eu.europa.ec.markt.tlmanager.view.certificate;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DigitalIdentityModel {

    private static final Logger LOG = Logger.getLogger(DigitalIdentityModel.class.getName());

    private DigitalIdentityType digitalIdentity;

    public DigitalIdentityModel() {
        digitalIdentity = new DigitalIdentityType();
    }

    public DigitalIdentityModel(DigitalIdentityType digitalIdentity) {
        this.digitalIdentity = digitalIdentity;
    }

    public X509Certificate getCertificate() {
        if (digitalIdentity.getX509Certificate() != null) {
            return DSSUtils.loadCertificate(digitalIdentity.getX509Certificate());
        } else {
            return null;
        }
    }

    public void setCertificate(X509Certificate certificate) {
        try {
            digitalIdentity.setX509Certificate(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public void updateDigitalIdentity() {
        LOG.info("updateDigitialIdentity");

    }

    public DigitalIdentityType getDigitalIdentity() {
        return digitalIdentity;
    }
}
