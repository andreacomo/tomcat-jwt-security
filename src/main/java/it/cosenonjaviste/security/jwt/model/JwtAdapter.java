package it.cosenonjaviste.security.jwt.model;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import it.cosenonjaviste.security.jwt.utils.JwtConstants;

import java.util.List;

public class JwtAdapter {

    private Algorithm algorithm;

    private DecodedJWT jwt;

    private String userIdClaim;

    private String rolesClaim;

    public JwtAdapter(Algorithm algorithm, DecodedJWT jwt) {
        this(algorithm, jwt, JwtConstants.USER_ID, JwtConstants.ROLES);
    }

    public JwtAdapter(Algorithm algorithm, DecodedJWT jwt, String userIdClaim, String rolesClaim) {
        this.algorithm = algorithm;
        this.jwt = jwt;
        this.userIdClaim = userIdClaim != null ? userIdClaim : JwtConstants.USER_ID;
        this.rolesClaim = rolesClaim != null ? rolesClaim: JwtConstants.ROLES;
    }

    /**
     * Convenience method to retrieve <tt>userId</tt> value from token claim
     *
     * @return <tt>userId</tt> value
     */
    public String getUserId() {
        return this.jwt.getClaim(userIdClaim).asString();
    }

    /**
     * Convenience method to retrieve <tt>roles</tt> value from token claim
     *
     * @return <tt>roles</tt> value collection
     */
    public List<String> getRoles() {
        return this.jwt.getClaim(rolesClaim).asList(String.class);
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

    /**
     * @return custom user id claim
     */
    public String getUserIdClaim() {
        return userIdClaim;
    }

    /**
     * @return custom roles claim
     */
    public String getRolesClaim() {
        return rolesClaim;
    }
}
