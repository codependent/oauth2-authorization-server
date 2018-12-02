package com.codependent.oauth2.authorizationserver;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.io.IOUtils;
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
import org.springframework.test.web.servlet.ResultMatcher;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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

        final String[] accessToken = executeImplicitFlow("operate");

        Assert.assertEquals("access_token", accessToken[0]);

        PublicKey pk = readPublicKey();
        final Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) pk, null);
        JWTVerifier verifier = JWT.require(algorithm).build(); //Reusable verifier instance
        verifier.verify(accessToken[1]);
    }

    @Test
    public void shouldFailWithInvalidScope() throws Exception {

        final String[] accessToken = executeImplicitFlow("admin");

        Assert.assertEquals("error", accessToken[0]);
        Assert.assertEquals("invalid_scope", accessToken[1]);

    }

    private String[] executeImplicitFlow(String scope) throws Exception {
        final MockHttpSession session = new MockHttpSession();

        final MvcResult result = getTokenUnauthorized(session, scope);
        final String location = result.getResponse().getHeader("Location");

        Assert.assertEquals("http://localhost/login", location);


        final MvcResult loginPageResult = getLocation(session, location, status().isOk());
        final String loginPageContent = loginPageResult.getResponse().getContentAsString();
        final String csrf = extractCsrf(loginPageContent);
        final MvcResult resultPostLogin = loginPost(session, csrf);
        final String locationPostLogin = resultPostLogin.getResponse().getHeader("Location");

        Assert.assertTrue("http://localhost/login", locationPostLogin.contains("/oauth/authorize"));

        final MvcResult authorizeResult = getLocation(session, locationPostLogin, status().isFound());
        final String authorizedLocation = authorizeResult.getResponse().getHeader("Location");
        URL authorizedUrl = new URL(authorizedLocation);
        final String fragment = authorizedUrl.getRef();
        final String[] fragments = fragment.split("&");
        return fragments[0].split("=");
    }



    private MvcResult getTokenUnauthorized(MockHttpSession session, String scope) throws Exception {
        String clientId = "front-app";
        String redirectUri = "http://localhost/tonr2/sparklr/photos";
        String responseType = "token";
        String state = "g720Jm";

        return this.mvc.perform(get(String.format(AUTH_PATH, clientId, redirectUri, responseType, scope, state))
                .session(session))
                .andExpect(status().isFound())
                .andReturn();
    }

    private MvcResult getLocation(MockHttpSession session, String location, ResultMatcher expectedStatus) throws Exception {
        return mvc.perform(get(location)
                .session(session))
                .andExpect(expectedStatus)
                .andReturn();
    }

    private MvcResult loginPost(MockHttpSession session, String csrf) throws Exception {
        return mvc.perform(post("http://localhost/login")
                .session(session)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("_csrf", csrf)
                .param("username", "jose")
                .param("password", "mypassword"))
                .andExpect(status().isFound())
                .andReturn();

    }

    private String extractCsrf(String body) {
        final Matcher matcher = CSRF_INPUT_REGEXP.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return null;
        }
    }

    private PublicKey readPublicKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {

        final InputStream pkIs = Thread.currentThread().getContextClassLoader().getResourceAsStream("public.crt");
        final String pkString = IOUtils.toString(pkIs, Charset.forName("UTF-8"));

        String publicKeyPEM = pkString.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

        BASE64Decoder b64 = new BASE64Decoder();
        byte[] decoded = b64.decodeBuffer(publicKeyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
