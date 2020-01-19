package it.cosenonjaviste.security.jwt.valves;

import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;
import it.cosenonjaviste.security.jwt.utils.JwtTokenBuilder;
import it.cosenonjaviste.security.jwt.utils.verifiers.JwtTokenVerifier;
import org.apache.catalina.connector.Response;

public class HmacJwtTokenValve extends JwtTokenValve {

    private String secret;

    private boolean updateExpire;

    @Override
    protected JwtTokenVerifier createTokenVerifier() {
        return JwtTokenVerifier.create(secret);
    }

    protected void beforeNext(Response response, JwtAdapter jwt) {
        if (this.updateExpire) {
            updateToken(jwt, response);
        }
    }

    private void updateToken(JwtAdapter jwtAdapter, Response response) {
        String newToken = JwtTokenBuilder.from(jwtAdapter).build();
        response.setHeader(JwtConstants.AUTH_HEADER, newToken);
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    /**
     * Updates expire time on each request
     *
     * @param updateExpire true to enable token update on each request
     */
    public void setUpdateExpire(boolean updateExpire) {
        this.updateExpire = updateExpire;
    }

}
