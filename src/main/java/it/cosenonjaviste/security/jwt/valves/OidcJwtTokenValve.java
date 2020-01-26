package it.cosenonjaviste.security.jwt.valves;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import it.cosenonjaviste.security.jwt.exceptions.ValveInitializationException;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import it.cosenonjaviste.security.jwt.utils.Preconditions;
import it.cosenonjaviste.security.jwt.utils.verifiers.JwtTokenVerifier;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * OpenId Connect idToken validation based on JWKS uri
 *
 * @author acomo
 */
public class OidcJwtTokenValve extends AbstractJwtTokenValve {

    private static final Log LOG = LogFactory.getLog(OidcJwtTokenValve.class);

    private URL issuerUrl;

    private Set<String> supportedAudiences;

    private int expiresIn;

    private TimeUnit timeUnit;

    private JwkProvider urlJwkProvider;

    public OidcJwtTokenValve() {
        defaults();
    }

    void defaults() {
        this.supportedAudiences = Collections.emptySet();
        this.expiresIn = 60;
        this.timeUnit = TimeUnit.MINUTES;
        this.customUserIdClaim = PublicClaims.SUBJECT;
        this.customRolesClaim = "authorities";
    }

    @Override
    protected void initInternal() throws LifecycleException {
        try {
            super.initInternal();
            this.urlJwkProvider = new JwkProviderBuilder(issuerUrl)
                    .cached(10, expiresIn, timeUnit)
                    .build();
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new ValveInitializationException(e.getMessage(), e);
        }
    }

    @Override
    protected void handleAuthentication(Request request, Response response) throws IOException, ServletException {
        try {
            Optional<DecodedJWT> optionalJwt = getJwtFrom(request);
            if (optionalJwt.isPresent()) {
                JwtAdapter jwtAdapter = verify(optionalJwt.get());
                authenticateRequest(request, jwtAdapter);

                this.getNext().invoke(request, response);
            } else {
                sendUnauthorizedError(request, response, "Authorization token not provided");
            }
        } catch (JwkException e) {
            LOG.error(e.getMessage(), e);
            sendUnauthorizedError(request, response, e.getMessage());
        } catch (JWTVerificationException e) {
            sendUnauthorizedError(request, response, e.getMessage());
        }
    }

    private JwtAdapter verify(DecodedJWT decodedJWT) throws JwkException {
        Jwk jwk = urlJwkProvider.get(decodedJWT.getKeyId());
        JwtAdapter verified = JwtTokenVerifier.create(newRsaKeyProvider(jwk), customUserIdClaim, customRolesClaim)
                .verify(decodedJWT);

        if (!supportedAudiences.isEmpty()) {
            String aud = decodedJWT.getClaim(PublicClaims.AUDIENCE).asString();
            if (!supportedAudiences.contains(aud)) {
                throw new InvalidClaimException("Audience claim value '" + aud + "' not supported");
            }
        }
        return verified;
    }

    private RSAKeyProvider newRsaKeyProvider(Jwk jwk) {
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String s) {
                try {
                    return (RSAPublicKey) jwk.getPublicKey();
                } catch (InvalidPublicKeyException e) {
                    throw new JWTDecodeException(e.getMessage(), e);
                }
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }

    private Optional<DecodedJWT> getJwtFrom(Request request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.toLowerCase().startsWith("bearer ")) {
            String jwt = bearerToken.replaceAll("(?i)Bearer (.*)", "$1");
            if (!jwt.isEmpty()) {
                return Optional.of(JWT.decode(jwt));
            } else {
                return Optional.empty();
            }
        } else {
            return Optional.empty();
        }
    }

    public void setIssuerUrl(String issuerUrl) throws MalformedURLException {
        this.issuerUrl = new URL(issuerUrl);
    }

    public void setSupportedAudiences(String supportedAudiences) {
        Preconditions.checkArgument(supportedAudiences != null, "supportedAudiences cannot be null");
        String[] split = supportedAudiences.split(",");
        this.supportedAudiences = Stream.of(split)
                .map(String::trim)
                .collect(Collectors.toSet());
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public void setTimeUnit(String timeUnit) {
        this.timeUnit = TimeUnit.valueOf(timeUnit);
    }
}
