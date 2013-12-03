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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.tlmanager.view.certificate.DigitalIdentityModel;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultipleModel;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 2519 $ - $Date: 2013-09-10 17:26:58 +0200 (Tue, 10 Sep 2013) $
 */
public class ServiceDigitalIdentityMultivalueAdapter implements MultipleModel<DigitalIdentityModel> {

    private static final Logger LOG = Logger.getLogger(ServiceDigitalIdentityMultivalueAdapter.class.getName());

    private final DigitalIdentityListType digitalIdentityList;
    private Map<String, DigitalIdentityModel> ids = new HashMap<String, DigitalIdentityModel>();

    private int i = 1;
    private boolean sn;
    private boolean ski;

    /**
     * The default constructor for ServiceDigitalIdentityMultivalueAdapter.
     */
    public ServiceDigitalIdentityMultivalueAdapter(DigitalIdentityListType digitalIdentityList, boolean useSn, boolean useSki) {
        this.digitalIdentityList = digitalIdentityList;
        initMultiModel(useSn, useSki);
    }

    private void initMultiModel(boolean useSn, boolean useSki) {
        final List<DigitalIdentityType> digitalIdList = digitalIdentityList.getDigitalId();
        for (DigitalIdentityType digitalIdentityType : digitalIdList) {
            final byte[] x509Certificate = digitalIdentityType.getX509Certificate();
            if (x509Certificate != null) {
                final DigitalIdentityModel digitalIdentityModel;
                digitalIdentityModel = new DigitalIdentityModel(digitalIdentityType);
                ids.put(createNewItem(), digitalIdentityModel);
            }
            if (useSki && digitalIdentityType.getX509SKI() != null) {
                ski = true;
            }
            if (useSki && StringUtils.isNotBlank(digitalIdentityType.getX509SubjectName())) {
                sn = true;
            }
        }
    }

    @Override
    public DigitalIdentityModel getValue(String key) {
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
        for (DigitalIdentityModel digitalIdentityModel : ids.values()) {
            if (digitalIdentityModel.getCertificate() != null) {
                size++;
            }
        }
        return size;
    }

    @Override
    public Dimension getRecommendedDialogSize() {
        return new Dimension(700, 500);
    }

    @Override
    public void setValue(String key, DigitalIdentityModel newDigitalIdentityModel) {
        LOG.info("Set value for key " + key + ": " + newDigitalIdentityModel);
        DigitalIdentityModel existingDigitalIdentityModel = ids.get(key);
        if (existingDigitalIdentityModel == null) {
            existingDigitalIdentityModel = new DigitalIdentityModel();
        }
        if (newDigitalIdentityModel.getCertificate() != null) {
            existingDigitalIdentityModel.setCertificate(newDigitalIdentityModel.getCertificate());
        }
        ids.put(key, existingDigitalIdentityModel);
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
        final List<DigitalIdentityType> digitalIdList = digitalIdentityList.getDigitalId();
        digitalIdList.clear();
        for (Map.Entry<String, DigitalIdentityModel> digitalIdentityModelEntry : ids.entrySet()) {
            final DigitalIdentityType digitalIdentityType = digitalIdentityModelEntry.getValue().getDigitalIdentity();
            digitalIdList.add(digitalIdentityType);
        }
        if (ski || sn) {
            boolean skiAdded = false;
            boolean snAdded = false;
            for (final DigitalIdentityType digitalIdentityType : digitalIdList) {
                X509Certificate certificate = DSSUtils.loadCertificate(digitalIdentityType.getX509Certificate());
                if (certificate != null) {
                    if (!snAdded && sn) {
                        final DigitalIdentityType digitalIdentitySN = new DigitalIdentityType();
                        final String x509SubjectName = certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
                        digitalIdentitySN.setX509SubjectName(x509SubjectName);
                        digitalIdList.add(digitalIdentitySN);
                        snAdded = true;
                    }

                    if (!skiAdded && ski) {
                        final byte[] skiValue = DSSUtils.getSki(certificate);
                        if (skiValue != null && skiValue.length > 0) {
                            final DigitalIdentityType digitalIdentitySKI = new DigitalIdentityType();
                            digitalIdentitySKI.setX509SKI(skiValue);
                            digitalIdList.add(digitalIdentitySKI);
                            skiAdded = true;
                        }
                    }
                }
                if (skiAdded && snAdded) {
                    break;
                }
            }
        }
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


    public DigitalIdentityListType getDigitalIdentityList() {
        return digitalIdentityList;
    }

    public boolean isSn() {
        return sn;
    }

    public boolean isSki() {
        return ski;
    }

    public void setSn(boolean sn) {
        this.sn = sn;
    }

    public void setSki(boolean ski) {
        this.ski = ski;
    }
}
