package eu.europa.ec.markt.dss.commons.swing.converter;

import java.util.List;

/**
 * 
 * 
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @param <S> source
 * @param <T> target
 */
public interface TreeCellConverter<S, T> {
    /**
     * 
     * @param source
     * @return
     */
    List<T> getChildren(S source);

}
