package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import java.awt.*;
import java.util.logging.Logger;

import eu.europa.ec.markt.tlmanager.view.certificate.DigitalIdentityModel;
import eu.europa.ec.markt.tlmanager.view.certificate.DigitalIdentityPanel;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DigitalIdentityContent extends MultiContent<DigitalIdentityModel> {

    private static final Logger LOG = Logger.getLogger(DigitalIdentityContent.class.getName());

    private final DigitalIdentityPanel panel;

    public DigitalIdentityContent() {
        panel = new DigitalIdentityPanel();
        panel.setName(panel.getClass().getSimpleName());
    }

    /** {@inheritDoc} */
    @Override
    public Component getComponent() {
        return panel;
    }

    @Override
    protected DigitalIdentityModel retrieveComponentValue(boolean clearOnExit) {
        DigitalIdentityModel model = panel.getDigitalIdentityModel();
        if (clearOnExit) {
            panel.setDigitalIdentityModel(new DigitalIdentityModel());
        }
        return model;
    }


    /** {@inheritDoc} */
    @Override
    protected void updateValue() {
        LOG.info("Update value for key " + currentKey);
        DigitalIdentityModel value = getValue(currentKey);

        if (value != null) {
            panel.setDigitalIdentityModel(value);
        } else {
            panel.setDigitalIdentityModel(new DigitalIdentityModel());
        }

    }

    @Override
    public String createNewItem() {
        ServiceDigitalIdentityMultivalueAdapter model = (ServiceDigitalIdentityMultivalueAdapter) getMultiValueModel();
        String key = model.createNewItem();
        setCurrentValue();
        currentKey = key;
        return key;
    }
}
