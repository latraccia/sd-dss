package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import java.awt.*;
import java.util.logging.Logger;

import eu.europa.ec.markt.tlmanager.view.panel.PoliciesListModel;
import eu.europa.ec.markt.tlmanager.view.panel.PoliciesListPanel;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class PoliciesListContent extends MultiContent<PoliciesListModel> {

    private static final Logger LOG = Logger.getLogger(PoliciesListContent.class.getName());

    private final PoliciesListPanel panel;

    public PoliciesListContent() {
        panel = new PoliciesListPanel();
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
    protected PoliciesListModel retrieveComponentValue(boolean clearOnExit) {
        PoliciesListModel model = panel.getPoliciesListModel();
        if (clearOnExit) {
            panel.setPoliciesListModel(new PoliciesListModel());
        }
        return model;
    }


    /** {@inheritDoc} */
    @Override
    protected void updateValue() {
        PoliciesListModel value = getValue(currentKey);
        if (value != null) {
            panel.setPoliciesListModel(value);
        } else {
            panel.setPoliciesListModel(new PoliciesListModel());
        }
    }

}
