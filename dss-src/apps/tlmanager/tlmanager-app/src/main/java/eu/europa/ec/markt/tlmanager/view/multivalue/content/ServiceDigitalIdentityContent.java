package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import java.awt.*;
import java.util.logging.Logger;

import eu.europa.ec.markt.tlmanager.view.certificate.ServiceDigitalIdentityPanel;
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
public class ServiceDigitalIdentityContent extends MultiContent<ServiceDigitalIdentityMultivalueAdapter> {

    private static final Logger LOG = Logger.getLogger(ServiceDigitalIdentityContent.class.getName());

    private final ServiceDigitalIdentityPanel panel;

    public ServiceDigitalIdentityContent() {
        panel = new ServiceDigitalIdentityPanel();
        panel.setName(panel.getClass().getSimpleName());
    }

    /** {@inheritDoc} */
    @Override
    public Component getComponent() {
        return panel;
    }

    @Override
    protected ServiceDigitalIdentityMultivalueAdapter retrieveComponentValue(boolean clearOnExit) {
        final ServiceDigitalIdentityMultivalueAdapter serviceDigitalIdentityMultivalueAdapter = panel
              .getServiceDigitalIdentityMultivalueAdapter();
        if (clearOnExit) {
            panel.setServiceDigitalIdentityMultivalueAdapter(
                  new ServiceDigitalIdentityMultivalueAdapter(new DigitalIdentityListType(), panel.isBoxSnSelected(),
                        panel.isBoxSkiSelected()));
        }
        return serviceDigitalIdentityMultivalueAdapter;
    }


    /** {@inheritDoc} */
    @Override
    protected void updateValue() {
        LOG.info("Update value for key " + currentKey);
        final ServiceDigitalIdentityMultivalueAdapter value = getValue(currentKey);

        if (value != null) {
            panel.setServiceDigitalIdentityMultivalueAdapter(value);
        } else {
            panel.setServiceDigitalIdentityMultivalueAdapter(
                  new ServiceDigitalIdentityMultivalueAdapter(new DigitalIdentityListType(), panel.isBoxSnSelected(),
                        panel.isBoxSkiSelected()));
        }

    }

    @Override
    public String createNewItem() {
        final ServiceDigitalIdentitiesMultivalueAdapter multiValueModel = (ServiceDigitalIdentitiesMultivalueAdapter) getMultiValueModel();
        String key = multiValueModel.createNewItem();
        setCurrentValue();
        currentKey = key;
        return key;
    }
}
