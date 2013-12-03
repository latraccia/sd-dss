/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: https://forge.aris-lux.lan/svn/dgmarktdss/trunk/apps/tlmanager/tlmanager-app/src/main/java/eu/europa/ec/markt/tlmanager/view/multivalue/content/DigitalIDMultivalueModel.java $
 * $Revision: 2519 $
 * $Date: 2013-09-10 17:26:58 +0200 (Tue, 10 Sep 2013) $
 * $Author: bouillni $
 */
package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import eu.europa.ec.markt.tlmanager.view.multivalue.MultipleModel;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceDigitalIdentityListType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 2519 $ - $Date: 2013-09-10 17:26:58 +0200 (Tue, 10 Sep 2013) $
 */
public class ServiceDigitalIdentitiesMultivalueAdapter implements MultipleModel<ServiceDigitalIdentityMultivalueAdapter> {

    private static final Logger LOG = Logger.getLogger(ServiceDigitalIdentitiesMultivalueAdapter.class.getName());

    private final ServiceDigitalIdentityListType serviceDigitalIdentityListType;
    private Map<String, ServiceDigitalIdentityMultivalueAdapter> ids = new HashMap<String, ServiceDigitalIdentityMultivalueAdapter>();

    private int i = 1;

    /**
     * The default constructor for ServiceDigitalIdentityMultivalueAdapter.
     */
    public ServiceDigitalIdentitiesMultivalueAdapter(ServiceDigitalIdentityListType serviceDigitalIdentityListType) {
        this.serviceDigitalIdentityListType = serviceDigitalIdentityListType;
        initMultiModel();
    }

    private void initMultiModel() {
        final List<DigitalIdentityListType> serviceDigitalIdentity = serviceDigitalIdentityListType
              .getServiceDigitalIdentity();
        for (DigitalIdentityListType digitalIdentityListType : serviceDigitalIdentity) {
            final ServiceDigitalIdentityMultivalueAdapter serviceDigitalIdentityMultivalueAdapter = new ServiceDigitalIdentityMultivalueAdapter(
                  digitalIdentityListType, true, true);
            ids.put(createNewItem(), serviceDigitalIdentityMultivalueAdapter);
        }
    }

    @Override
    public ServiceDigitalIdentityMultivalueAdapter getValue(String key) {
        return ids.get(key);
    }

    @Override
    public List<String> getKeys() {
        List<String> keys = new ArrayList<String>();
        for (String k : ids.keySet()) {
            keys.add(k);
        }
        return keys;
    }

    @Override
    public int size() {
        int size = 0;
        for (ServiceDigitalIdentityMultivalueAdapter serviceDigitalIdentityMultivalueAdapter : ids.values()) {
            if (serviceDigitalIdentityMultivalueAdapter.size() > 0) {
                size++;
            }
        }
        return size;
    }

    @Override
    public Dimension getRecommendedDialogSize() {
        return new Dimension(666, 400);
    }

    @Override
    public void setValue(String key,
                         ServiceDigitalIdentityMultivalueAdapter newServiceDigitalIdentityMultivalueAdapter) {
        LOG.info("Set value for key " + key + ": " + newServiceDigitalIdentityMultivalueAdapter);
        ServiceDigitalIdentityMultivalueAdapter existingDigitalIdentitiesModel = ids.get(key);
        if (existingDigitalIdentitiesModel == null) {
            existingDigitalIdentitiesModel = new ServiceDigitalIdentityMultivalueAdapter(new DigitalIdentityListType(),
                  newServiceDigitalIdentityMultivalueAdapter.isSn(), newServiceDigitalIdentityMultivalueAdapter.isSki());
        }
        if (newServiceDigitalIdentityMultivalueAdapter.getDigitalIdentityList() != null) {
            existingDigitalIdentitiesModel = newServiceDigitalIdentityMultivalueAdapter;
        }
        ids.put(key, existingDigitalIdentitiesModel);
    }

    @Override
    public String getInitialValueKey() {
        if (ids.keySet().isEmpty()) {
            return null;
        } else {
            return ids.keySet().iterator().next();
        }
    }

    @Override
    public void removeItem(String key) {
        ids.remove(key);
    }

    @Override
    public void updateBeanValues() {
        LOG.info("Update bean value");
        final List<DigitalIdentityListType> serviceDigitalIdentity = serviceDigitalIdentityListType
              .getServiceDigitalIdentity();
        serviceDigitalIdentity.clear();
        serviceDigitalIdentity.addAll(generateServiceDigitalIdentityListType().getServiceDigitalIdentity());
    }

    @Override
    public String createNewItem() {
        String key = "Item " + i++;
        return key;
    }

    @Override
    public boolean isEmpty() {
        return size() == 0;
    }

    /**
     *
     * @return a ServiceDigitalIdentityListType with the content of the adapter
     */
    private ServiceDigitalIdentityListType generateServiceDigitalIdentityListType() {
        ServiceDigitalIdentityListType result = new ServiceDigitalIdentityListType();
        for (final ServiceDigitalIdentityMultivalueAdapter serviceDigitalIdentityMultivalueAdapter : ids.values()) {
            if (serviceDigitalIdentityMultivalueAdapter.size() > 0) {
                final DigitalIdentityListType digitalIdentityList = serviceDigitalIdentityMultivalueAdapter
                      .getDigitalIdentityList();
                result.getServiceDigitalIdentity().add(digitalIdentityList);
            }
        }
        return result;
    }

}
