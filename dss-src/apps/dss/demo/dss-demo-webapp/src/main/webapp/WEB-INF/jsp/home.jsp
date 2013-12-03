<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2><spring:message code="label.info"/></h2>
<p>Please see the notes below for the features of the two applications:</p>
<div class="fluid-row">
	<div class="fluid-column fluid-c6">
		<h3><spring:message code="label.tlmanager"/></h3>
			<ul>
				<li>A Trusted List and List of the List can be created from scratch.</li>
				<li>An existing TSL can be loaded, edited, signed and saved.</li>
				<li>A basic validation is performed at the first step of creating a signature.</li>
			</ul>
	</div>
	<div class="fluid-column fluid-c6">		
		<div class="column">
			<h3><spring:message code="label.signature.applet"/></h3>
			<ul>
				<li>XML files can be signed with an enveloped/enveloping/detached XAdES signature.</li>
				<li>PDF files can be signed with an enveloped PAdES signature.</li>
				<li>Arbitrary binary files can be signed with an enveloping/detached CAdES signature or ASiC-S</li>
				<li>A user can use PKCS#11-compliant SSCD, MSCAPI and PKCS#12 to sign.</li>
				<li>Validation report is available on CAdES, PAdES, XAdES signature.</li>
			</ul>
		</div>
	</div>
</div>