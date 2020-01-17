package it.cosenonjaviste.security.jwt.model;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;

import java.util.List;

public class JwtAdapter {

    private Algorithm algorithm;

    private DecodedJWT jwt;

    public JwtAdapter(Algorithm algorithm, DecodedJWT jwt) {
        this.algorithm = algorithm;
        this.jwt = jwt;
    }

    /**
     * Convenience method to retrieve <tt>userId</tt> value from token claim
     *
     * @return <tt>userId</tt> value
     */
    public String getUserId() {
        return this.jwt.getClaim(JwtConstants.USER_ID).asString();
    }

    /**
     * Convenience method to retrieve <tt>roles</tt> value from token claim
     *
     * @return <tt>roles</tt> value collection
     */
    public List<String> getRoles() {
        return this.jwt.getClaim(JwtConstants.ROLES).asList(String.class);
    }

    /**
     * Return validated decodedJWT
     *
     * @return DecodedJWT instance
     */
    public DecodedJWT getDecodedJWT() {
        return this.jwt;
    }

    /**
     * @return algorithm used for encoding the token
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }
}
