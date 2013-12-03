package eu.europa.ec.markt.dss.mocca;

import eu.europa.ec.markt.dss.signature.token.PasswordInputCallback;

import at.gv.egiz.smcc.CancelledException;
import at.gv.egiz.smcc.PinInfo;
import at.gv.egiz.smcc.pin.gui.PINGUI;

/**
 * This class provides automatically the PIN code. Only one call can be done. This protects the card against its
 * blocking.<br>
 * 1811/Do not throw a runtime exception when number of password tries exceeds 1 because it is unfriendly to the user
 * who has just entered the wrong PIN. (DUAT - AT reported the problem)<br>
 * 1809/Remove the RuntimeException throw when retries>1 (DG Justice DSS DUAT Testing)<br>
 * FIXME: These two issues need to be solved.
 * 
 * @author bielecro
 * 
 */
class PINGUIAdapter implements PINGUI {

   private PasswordInputCallback callback;

   private int retries = 0;

   private boolean alreadyAsked = false;

   public PINGUIAdapter(PasswordInputCallback callback) {
      this.callback = callback;
   }

   @Override
   public char[] providePIN(PinInfo pinSpec, int retries) throws CancelledException, InterruptedException {
      this.retries = retries;
      if (alreadyAsked) {

         throw new RuntimeException("Asked already!");
      }
      alreadyAsked = true;
      return callback.getPassword();
   }

   @Override
   public void enterPINDirect(PinInfo pinInfo, int retries) throws CancelledException, InterruptedException {

   }

   @Override
   public void enterPIN(PinInfo pinInfo, int retries) throws CancelledException, InterruptedException {
   }

   @Override
   public void validKeyPressed() {
   }

   @Override
   public void correctionButtonPressed() {
   }

   @Override
   public void allKeysCleared() {
   }

   public int getRetries() {
      return retries;
   }
}
