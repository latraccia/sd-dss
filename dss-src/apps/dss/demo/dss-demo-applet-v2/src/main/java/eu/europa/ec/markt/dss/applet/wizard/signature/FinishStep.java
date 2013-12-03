package eu.europa.ec.markt.dss.applet.wizard.signature;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class FinishStep extends WizardStep<SignatureModel, SignatureWizardController> {

	/**
	 * 
	 * The default constructor for SignStep.
	 * 
	 * @param model
	 * @param view
	 * @param controller
	 */
	public FinishStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view,
			final SignatureWizardController controller) {

		super(model, view, controller);
	}

	@Override
	protected void finish() throws ControllerException {

		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
	 */
	@Override
	protected void init() throws ControllerException {

		// FIXME
		try {
			getController().signDocument();
		} catch (final IOException e) {
			throw new ControllerException(e);
		} catch (final NoSuchAlgorithmException e) {
			throw new ControllerException(e);
		} catch (DSSException e) {
			throw new ControllerException(e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {

		return SaveStep.class;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
	 */
	@Override
	protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {

		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
	 */
	@Override
	protected int getStepProgression() {

		return 7;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
	 */
	@Override
	protected boolean isValid() {

		return false;
	}

}
