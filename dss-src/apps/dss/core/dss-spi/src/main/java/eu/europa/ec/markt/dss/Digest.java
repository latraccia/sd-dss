/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/trunk/buildtools/src/main/resources/eclipse/dss-java-code-template.xml $
 * $Revision: 672 $
 * $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * $Author: hiedelch $
 */
package eu.europa.ec.markt.dss;

/**
 * Container for a Digest and his algorithm
 *  
 * <p>DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class Digest {

    private DigestAlgorithm algorithm;
    
    private byte[] value;

    /**
     * The default constructor for Digest.
     */
    public Digest() {
    }
    
    public Digest(DigestAlgorithm algorithm, byte[] value) {
        super();
        this.algorithm = algorithm;
        this.value = value;
    }

    /**
     * @return the algorithm
     */
    public DigestAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * @param algorithm the algorithm to set
     */
    public void setAlgorithm(DigestAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * @return the value
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(byte[] value) {
        this.value = value;
    }
    
}
