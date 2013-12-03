package eu.europa.ec.markt.tlmanager.view.binding;

import org.jdesktop.beansbinding.Converter;

import eu.europa.ec.markt.tlmanager.view.multivalue.content.ServiceDigitalIdentityMultivalueAdapter;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ServiceDigitalIdentityConverter extends Converter<DigitalIdentityListType, ServiceDigitalIdentityMultivalueAdapter> {

    private final boolean useSn;
    private final boolean useSki;

    public ServiceDigitalIdentityConverter(boolean useSn, boolean useSki) {
        this.useSn = useSn;
        this.useSki = useSki;
    }

    @Override
    public ServiceDigitalIdentityMultivalueAdapter convertForward(DigitalIdentityListType value) {
        return new ServiceDigitalIdentityMultivalueAdapter(value, useSn, useSki);
    }

    @Override
    public DigitalIdentityListType convertReverse(ServiceDigitalIdentityMultivalueAdapter value) {
        return value.getDigitalIdentityList();
    }
}
