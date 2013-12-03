<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>



<div class="fluid-row">
	<div class="fluid-column fluid-c12">
	
		<h1><spring:message code="label.tsls"/></h1>
		<div class="table-container">
			<table class="data-table">
				<thead>
					<tr>
						<th><spring:message code="label.tsl"/></th>
						<th><spring:message code="label.info"/></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<c:forEach items="${tsls}" var="tsl">
					<tr>
						<td>${tsl.key}</td>
						<td>${tsl.value}</td>
					</tr>
					</c:forEach>
				</tbody>
			</table>		
		</div>

		<h1><spring:message code="label.certificates"/></h1>
		<div class="table-container">
			<table class="data-table">
				<thead>
					<tr>
						<th><spring:message code="label.service"/></th>
						<th><spring:message code="label.issuer"/></th>
						<th><spring:message code="label.validity_start"/></th>
						<th><spring:message code="label.validity_end"/></th>
					</tr>
				</thead>
				<tbody>
					<c:forEach items="${certs}" var="cert">
					<tr>
						<td>${cert.certificate.subjectDN.name}</td>
						<td>${cert.certificate.issuerDN.name}</td>
						<td>${cert.certificate.notBefore}</td>
						<td>${cert.certificate.notAfter}</td>
					</tr>
					</c:forEach>
				</tbody>
			</table>		
		</div>

	</div>
</div>
