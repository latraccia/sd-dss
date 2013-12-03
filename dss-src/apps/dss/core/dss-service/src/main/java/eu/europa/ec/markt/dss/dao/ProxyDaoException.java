package eu.europa.ec.markt.dss.dao;
/**
 * 
 * Exception thrown for errors in the ProxyDao
 *  
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1688 $ - $Date: 2013-02-14 13:21:02 +0100 (jeu., 14 févr. 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ProxyDaoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * 
     * The constructor for ProxyDaoException.
     * @param cause the underlying cause.
     */
    public ProxyDaoException (Throwable cause){
        super(cause);
    }
}
