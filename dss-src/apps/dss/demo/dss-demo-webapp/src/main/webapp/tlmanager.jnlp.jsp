<%@page contentType="application/x-java-jnlp-file"%><%
 String tlMode = request.getParameter("tlMode");
 String euMode = request.getParameter("euMode");
 response.setHeader("content-disposition", "attachment;filename=tlmanager-" + euMode + "-" + tlMode + ".jnlp");
 StringBuilder codebaseBuffer = new StringBuilder();
 codebaseBuffer.append(!request.isSecure() ? "http://" : "https://");
 codebaseBuffer.append(request.getServerName());
 if (request.getServerPort() != (!request.isSecure() ? 80 : 443))
 {
   codebaseBuffer.append(':');
   codebaseBuffer.append(request.getServerPort());
 }
 String contextPath = request.getRequestURI();
 if(contextPath.contains("/")) {
     contextPath = contextPath.substring(0, contextPath.lastIndexOf("/"));
 }
 codebaseBuffer.append(contextPath);
%><?xml version="1.0" encoding="UTF-8"?>
<jnlp spec="1.0+" codebase="<%= codebaseBuffer.toString() %>">

    <information>
        <title>Trusted List Manager</title>
        <vendor>Arhs Developments</vendor>
    </information>
    
    <resources>
        <j2se version="1.6+"
              href="http://java.sun.com/products/autodl/j2se"/>
        <jar href="jar/tlmanager-package-r5.jar" main="true" />
        <property name="tlmanager.common.mode" value="<%=tlMode%>"/>
        <property name="tlmanager.common.territory" value="<%=euMode%>"/>
    </resources>
    
    <application-desc
         name="TLManager"
         main-class="eu.europa.ec.markt.tlmanager.TLManager"
         width="800"
         height="600">
     </application-desc>
     
     <update check="background"/>
     
    <security>
    	<all-permissions/>
	</security>
    
</jnlp>