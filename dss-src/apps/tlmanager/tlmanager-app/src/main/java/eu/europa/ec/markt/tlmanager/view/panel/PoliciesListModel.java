package eu.europa.ec.markt.tlmanager.view.panel;

import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class PoliciesListModel implements ContentModel {

    private final PoliciesListType policiesListType;

    public PoliciesListModel() {
        this.policiesListType = new PoliciesListType();
    }

    public PoliciesListModel(final PoliciesListType keyUsageType) {
        this.policiesListType = keyUsageType;
    }

    public PoliciesListModel(final PoliciesListModel policiesListModel) {
        this.policiesListType = policiesListModel.policiesListType;
    }


    @Override
    public boolean isEmpty() {
        return policiesListType == null || policiesListType.getPolicyIdentifier() == null || policiesListType.getPolicyIdentifier().isEmpty();
    }

    @Override
    public void clear() {
        if (policiesListType != null && policiesListType.getPolicyIdentifier() != null) {
            policiesListType.getPolicyIdentifier().clear();
        }
    }

    public PoliciesListType getPoliciesListType() {
        return policiesListType;
    }
}
