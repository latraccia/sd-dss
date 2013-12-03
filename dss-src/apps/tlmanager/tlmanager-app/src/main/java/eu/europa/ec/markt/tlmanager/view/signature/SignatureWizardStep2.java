/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.tlmanager.view.signature;

import eu.europa.ec.markt.dss.common.PinInputDialog;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.tlmanager.core.signature.SignatureManager;

import java.awt.Component;
import java.io.File;
import java.util.logging.Logger;

import javax.swing.event.ChangeListener;

import org.openide.WizardDescriptor.ValidatingPanel;
import org.openide.WizardValidationException;
import org.openide.util.HelpCtx;

/**
 * The second step of the signature wizard.
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public class SignatureWizardStep2 implements ValidatingPanel<Object> {

    private static final Logger LOG = Logger.getLogger(SignatureWizardStep2.class.getName());

    private SignatureManager manager;
    private SignatureStep2 panel;
    private PinInputDialog pinInputDialog;

    /**
     * The default constructor for SignatureWizardStep2.
     */
    public SignatureWizardStep2(SignatureManager manager) {
        this.manager = manager;
        panel = new SignatureStep2(this);
        pinInputDialog = new PinInputDialog(panel);
        manager.setPwCallback(pinInputDialog);
    }

    /**
     * Sets a value for the Signature Provider.
     * 
     * @param provider the provider
     */
    public void setSigProvider(SignatureTokenType provider) {
        manager.setProvider(provider);
    }

    /**
     * @return the source file.
     */
    public File getSourceFile() {
        return manager.getMatchingSource();
    }

    /**
     * Sets the pkcs11 library file.
     * 
     * @param source the pkcs11 library file
     */
    public void setPkcs11Library(File source) {
        manager.setPkcs11Library(source);
    }

    /**
     * Sets the pkcs12 library file.
     * 
     * @param source the pkcs12 library file
     */
    public void setPkcs12File(File source) {
        manager.setPkcs12File(source);
    }

    /**
     * Sets the password.
     * 
     * @param password the new password
     */
    public void setPassword(char[] password) {
        manager.setPassword(password);
    }

    /** @{inheritDoc */
    @Override
    public void addChangeListener(ChangeListener arg0) {
    }

    /** @{inheritDoc */
    @Override
    public Component getComponent() {
        return panel;
    }

    /** @{inheritDoc */
    @Override
    public HelpCtx getHelp() {
        return null;
    }

    /** @{inheritDoc */
    @Override
    public boolean isValid() {
        return true;
    }

    /** @{inheritDoc */
    @Override
    public void readSettings(Object arg0) {
    }

    /** @{inheritDoc */
    @Override
    public void removeChangeListener(ChangeListener arg0) {
    }

    /** @{inheritDoc */
    @Override
    public void storeSettings(Object arg0) {
    }

    /** @{inheritDoc */
    @Override
    public void validate() throws WizardValidationException {
        setPassword(panel.getPassword());
        if (manager.getProvider() != null) {
            SignatureTokenType provider = manager.getProvider();
            if (!provider.equals(SignatureTokenType.MSCAPI) && !manager.isAnySource()) {
                throw new WizardValidationException(null, "No valid source selected!", null);
            }
            if (provider.equals(SignatureTokenType.PKCS12)
                    && (manager.getPassword() == null || manager.getPassword().length == 0)) {
                throw new WizardValidationException(null, "No password provided for PKCS12!", null);
            }
        } else {
            throw new WizardValidationException(null, "No provider selected!", null);
        }

        try {
            manager.getCertificates();
        } catch (Exception ex) {
            throw new WizardValidationException(null, "Exception: " + ex.getMessage(), null);
        }
    }
}