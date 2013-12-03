package eu.europa.ec.markt.tlmanager.view.panel;

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
public class KeyUsageModel implements ContentModel {

    private final KeyUsageType keyUsageType;

    public KeyUsageModel() {
        this.keyUsageType = new KeyUsageType();
    }

    public KeyUsageModel(final KeyUsageType keyUsageType) {
        this.keyUsageType = keyUsageType;
    }

    public KeyUsageModel(final KeyUsageModel keyUsageModel) {
        this.keyUsageType = keyUsageModel.keyUsageType;
    }


    @Override
    public boolean isEmpty() {
        return keyUsageType == null || keyUsageType.getKeyUsageBit() == null || keyUsageType.getKeyUsageBit().isEmpty();
    }

    @Override
    public void clear() {
        if (keyUsageType != null && keyUsageType.getKeyUsageBit() != null) {
            keyUsageType.getKeyUsageBit().clear();
        }
    }

    public KeyUsageType getKeyUsageType() {
        return keyUsageType;
    }
}
