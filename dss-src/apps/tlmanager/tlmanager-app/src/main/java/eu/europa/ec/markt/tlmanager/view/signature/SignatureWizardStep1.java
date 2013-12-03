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

import eu.europa.ec.markt.tlmanager.core.signature.SignatureManager;

import java.awt.Component;
import java.util.logging.Logger;

import javax.swing.event.ChangeListener;

import org.openide.WizardDescriptor.ValidatingPanel;
import org.openide.WizardValidationException;
import org.openide.util.HelpCtx;

/**
 * The first step of the signature wizard.
 * 
 *
 * @version $Revision: 1036 $ - $Date: 2011-06-22 11:30:02 +0200 (mer., 22 juin 2011) $
 */

public class SignatureWizardStep1 implements ValidatingPanel<Object> {

    private static final Logger LOG = Logger.getLogger(SignatureWizardStep1.class.getName());

    private SignatureManager manager;
    private SignatureStep1 panel;
    private boolean overrideEnabled = false;

    /**
     * The default constructor for SignatureWizardStep1.
     */
    public SignatureWizardStep1(SignatureManager manager) {
        this.manager = manager;
        panel = new SignatureStep1(this);
    }

    
    /**
     * Enables overriding the blocking behaviour of validation in case of errors.
     * @param override true if it is ok to override
     */
    public void overrideEnabled(boolean override) {
        overrideEnabled = override;
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
        panel.setValidationMessages(manager.retrieveValidationMessages());
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
        if (manager.isValidationErroneous() && !overrideEnabled) {
            
            // don't allow to continue
            throw new WizardValidationException(null,
                    "As the validation contains errors, it is not possible to continue!", null);
        }
    }
}