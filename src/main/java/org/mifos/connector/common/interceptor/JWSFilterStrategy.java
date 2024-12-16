package org.mifos.connector.common.interceptor;

import java.io.IOException;
import java.util.List;
//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.ServletRequest;
//import javax.servlet.ServletResponse;
//import javax.servlet.http.HttpServletResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.mifos.connector.common.interceptor.service.JsonWebSignatureService;
import org.mifos.connector.common.util.Constant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.ContentCachingResponseWrapper;

@Component
@ConditionalOnExpression("'${security.jws.enable:true}' == 'true' and '${security.jws.response.enable:true}' == 'true'")
@Slf4j
public class JWSFilterStrategy extends GenericFilterBean {

    @Value("#{'${jws.header.order}'.split(',')}")
    private List<String> headerOrder;

    @Autowired
    private JsonWebSignatureService jsonWebSignatureService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.debug("Started JWSFilterStrategy.doFilter");

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(httpResponse);

        // Proceed with the filter chain
        chain.doFilter(request, wrappedResponse);

        try {
            // Read response body
            byte[] responseBytes = wrappedResponse.getContentAsByteArray();
            String charset = httpResponse.getCharacterEncoding() != null ? httpResponse.getCharacterEncoding() : "UTF-8";
            String responseBody = new String(responseBytes, charset);

            // Fetch tenant header
            String tenant = httpResponse.getHeader(Constant.HEADER_PLATFORM_TENANT_ID);
            log.debug("Platform-TenantId: {}", tenant);

            // Create JWS
            String dataToBeHashed = JWSUtil.getDataToBeHashed(httpResponse, responseBody, headerOrder);
            String signature = jsonWebSignatureService.signForTenant(dataToBeHashed, tenant);

            // Append JWS header
            wrappedResponse.setHeader(Constant.HEADER_JWS, signature);
            log.debug("JWS Signature: {}", signature);

        } catch (Exception e) {
            log.error("Error while creating JWS signature: {}", e.getMessage(), e);
        } finally {
            // Copy response body to the actual response
            wrappedResponse.copyBodyToResponse();
        }

        log.debug("Ended JWSFilterStrategy.doFilter");
    }
}
