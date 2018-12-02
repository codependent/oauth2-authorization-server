package com.codependent.oauth2.authorizationserver;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AuthorizationServerApplicationTests {

    private static final Pattern CSRF_INPUT_REGEXP = Pattern.compile("<input type=\"hidden\" name=\"_csrf\" value=\"(.*)\"/>");
    private static final String AUTH_PATH = "/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s";

    @Autowired
    private MockMvc mvc;

    @Test
    public void shouldReturnValidJwtToken() throws Exception {

        final MockHttpSession session = new MockHttpSession();
        String clientId = "front-app";
        String redirectUri = "http://localhost/tonr2/sparklr/photos";
        String responseType = "token";
        String scope = "operate";
        String state = "g720Jm";

        final MvcResult result = this.mvc.perform(get(String.format(AUTH_PATH, clientId, redirectUri, responseType, scope, state))
                .session(session))
                .andExpect(status().isFound())
                .andReturn();

        System.out.println(result.getResponse().getHeaderNames());
        final String location = result.getResponse().getHeader("Location");
        Assert.assertEquals("http://localhost/login", location);


        final MvcResult loginPageResult = mvc.perform(get(location)
                .session(session))
                .andExpect(status().isOk())
                .andReturn();

        System.out.println(result.getResponse().getHeaderNames());
        final String loginPageContent = loginPageResult.getResponse().getContentAsString();
        final Matcher matcher = CSRF_INPUT_REGEXP.matcher(loginPageContent);
        matcher.find();
        final String csrf = matcher.group(1);


        final MvcResult resultPostLogin = mvc.perform(post("http://localhost/login")
                .session(session)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("_csrf", csrf)
                .param("username", "jose")
                .param("password", "mypassword"))
                .andExpect(status().isFound())
                .andReturn();

        final String locationPostLogin = resultPostLogin.getResponse().getHeader("Location");
        Assert.assertTrue("http://localhost/login", locationPostLogin.contains("/oauth/authorize"));

        final MvcResult authorizeResult = mvc.perform(get(locationPostLogin)
                .session(session))
                .andExpect(status().isFound())
                .andReturn();

        System.out.println(authorizeResult.getResponse().getHeaderNames());
        final String authorizedLocation = authorizeResult.getResponse().getHeader("Location");

        URL authorizedUrl = new URL(authorizedLocation);
        final String fragment = authorizedUrl.getRef();
        final String[] fragments = fragment.split("&");

        final String[] accessToken = fragments[0].split("=");
        Assert.assertEquals("access_token", accessToken[0]);
        Assert.assertNotNull(accessToken[1]);

    }


}
