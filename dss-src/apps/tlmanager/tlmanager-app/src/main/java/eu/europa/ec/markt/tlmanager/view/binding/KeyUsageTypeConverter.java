package eu.europa.ec.markt.tlmanager.view.binding;

import java.util.List;

import org.jdesktop.beansbinding.Converter;

import eu.europa.ec.markt.tlmanager.model.KeyUsageTypeAdapter;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class KeyUsageTypeConverter extends Converter<List<KeyUsageType>, KeyUsageTypeAdapter> {

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyUsageTypeAdapter convertForward(List<KeyUsageType> source) {
        return new KeyUsageTypeAdapter(source);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<KeyUsageType> convertReverse(KeyUsageTypeAdapter target) {
        return target.getKeyUsageTypeList();
    }
}
