package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import java.awt.*;
import java.util.logging.Logger;

import eu.europa.ec.markt.tlmanager.view.panel.KeyUsageModel;
import eu.europa.ec.markt.tlmanager.view.panel.KeyUsagePanel;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class KeyUsageContent extends MultiContent<KeyUsageModel> {

    private static final Logger LOG = Logger.getLogger(KeyUsageContent.class.getName());

    private final KeyUsagePanel panel;

    public KeyUsageContent() {
        panel = new KeyUsagePanel();
        panel.setName(panel.getClass().getSimpleName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Component getComponent() {
        return panel;
    }

    @Override
    protected KeyUsageModel retrieveComponentValue(boolean clearOnExit) {
        KeyUsageModel model = panel.retrieveCurrentValues();
        if (clearOnExit) {
            panel.updateCurrentValues(new KeyUsageModel());
        }
        return model;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected void updateValue() {
        KeyUsageModel value = getValue(currentKey);
        if (value != null) {
            panel.updateCurrentValues(value);
        } else {
            panel.clearModel();
        }
    }

}
