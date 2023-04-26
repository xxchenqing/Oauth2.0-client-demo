package com.example.oauth2demo.filter;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@WebFilter(filterName = "oauthFilter", urlPatterns = {"*.css","*.jpg","*.js"})
@Configuration
@Order(1)
public class OauthFilter implements Filter {
    private String clientId = "f1062467b5bb6f0d65a8c4d273d3a16e";
    private String clientSecret = "f34a68eaa1081ec76a989190d78036ea";
    private String authorizeUrl = "http://localhost:7002/auth/login";
    private String tokenUrl = "http://127.0.0.1:7002/auth/api/v2/token";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException {
        {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            OAuthClientRequest oauthRequest = null;
            try {
                HttpSession session = httpRequest.getSession();
                if (session == null || session.getAttribute("access_token") == null) {
                    String code = request.getParameter("code");
                    if (code != null) {
                        String redirectUri = request.getParameter("redirect_uri");
                        oauthRequest = OAuthClientRequest
                                .tokenLocation(tokenUrl)
                                .setGrantType(GrantType.AUTHORIZATION_CODE)
                                .setClientId(clientId)
                                .setClientSecret(clientSecret)
                                .setRedirectURI(redirectUri)
                                .setCode(code)
                                .buildBodyMessage();


                        OAuthClient oauthClient = new OAuthClient(new URLConnectionClient());
                        OAuthJSONAccessTokenResponse oauthResponse = null;
                        oauthResponse = oauthClient.accessToken(oauthRequest);
                        String accessToken = oauthResponse.getAccessToken();
                        session.setAttribute("access_token", accessToken);

                        chain.doFilter(request, response);
                    }

                    // If not authenticated, redirect the user to the OAuth2 server
                    oauthRequest = OAuthClientRequest
                            .authorizationLocation(authorizeUrl)
                            .setClientId(clientId)
                            .setRedirectURI("http://localhost:8080" + httpRequest.getRequestURI())
                            .setResponseType("code")
                            .setScope("openid")
                            .buildQueryMessage();
                    httpResponse.sendRedirect(oauthRequest.getLocationUri());
                } else {
                    // If authenticated, continue with the request
                    chain.doFilter(request, response);
                }
            } catch (Exception e) {
                httpResponse.sendRedirect(oauthRequest.getLocationUri());
            }
        }
    }
}
