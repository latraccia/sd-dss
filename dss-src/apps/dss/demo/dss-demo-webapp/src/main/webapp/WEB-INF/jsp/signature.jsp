<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h1 class="center">
	<spring:message code="label.signature.applet" />
</h1>
<div class="fluid-row center">
	<div class="fluid-column fluid-c12">
		<script type="text/javascript"
			src="<spring:url value="/scripts/deployJava.js"/>"></script>
		<script type="text/javascript">
			var attributes = {
				code : 'eu.europa.ec.markt.dss.applet.main.DSSAppletCore.class',
				archive : 'jar/signature-applet-r5.jar,jar/bcprov-jdk16.jar,jar/bcmail-jdk16.jar,jar/bctsp-jdk16.jar,jar/sscd-mocca-adapter.jar',
				width : 800,
				height : 600
			};
			var parameters = {
				service_url : '<c:out value="${prefUrlService.value}"/>',
                default_policy_url : '<c:out value="${prefDefaultPolicyUrl}"/>',
            };
			var version = '1.6';

			deployJava.runApplet(attributes, parameters, version);
		</script>
	</div>
</div>
<div class="fluid-row">
	<div class="fluid-column fluid-c12">
		<div class="common-box">
			<p>
				If you don't have access to a SSCD, you can try the signature with a
				PKCS#12 package. <a href="0F.p12" target="p12-download">Here is
					a sample PKCS#12 file</a> that you can use for signing. You can just
				download the file and select the PKCS#12 signature token API in step
				3. The password for accessing the certificates inside the file is
				"password".
			</p>
			<p>Note: You should enable showing the Java console via the Java
				plugin settings.</p>
		</div>

		<div id="mocca-integration" class="common-box">
			<p>
				If your Smartcard is supported by MOCCA, you can use it to
				communicate with your smartcard. See <a
					href="https://joinup.ec.europa.eu/software/sd-dss/wiki/mocca-smartcard-integration">wiki/mocca-smartcard-integration</a>
				for more information.
			</p>
		</div>

		<div id="compatibility_warning" style="display: none;">
			<div class="highlight-box">
				<h3>Warning</h3>
				<p>It seems that your environment does not meet the
					requirements:</p>

				<p>
					<ul>
                    	<li>Java Version: 1.6</li>
                     	<li>Browser: Internet Explorer (from version 6) or Mozilla Firefox (from version 3.0)</li>
                     	<li>Architecture: 32 or 64 bit</li>
                 	</ul>
                 </p>
                 <p>We found the following information:</p>
                 <p id="compatibility_found"></p>
                 <p>Anyway, we tried to start the applet (should be displayed on the left).</p>
             </div>
         </div>

         <script type="text/javascript">
										function checkRequirements() {
											var browser = jQuery.browser;
											var version = parseInt(detectBrowserVersion());

											var compatibleBrowser = false;
											if (browser.msie) {
												if (version >= 6) {
													compatibleBrowser = true;
												}
											} else if (browser.mozilla) {
												if (version >= 3) {
													compatibleBrowser = true;
												}
											}
											var compatibleJava = navigator
													.javaEnabled();

											if (compatibleBrowser
													&& compatibleJava) {
												return;
											}

											jQuery("#compatibility_found")
													.html(navigator.userAgent);
											jQuery("#compatibility_warning")
													.show("bounce", null,
															"fast");
										}

										checkRequirements();
									</script></div>   

				
   </div>
 

<h2><spring:message code="label.info" /></h2>

<div id="compatibility" class="common-box">
	<p>
		For the latest information about DSS compatibility, please consult the pages : 
		<ul>
			<li><a href="https://joinup.ec.europa.eu/software/sd-dss/wiki/smartcard-compatibility">wiki/smartcard-compatibility</a></li>
			<li><a href="https://joinup.ec.europa.eu/software/sd-dss/wiki/applet-compatibility">wiki/applet-compatibility</a></li>
		</ul>
	</p>
</div>

