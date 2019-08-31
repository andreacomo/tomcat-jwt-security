package it.cosenonjaviste.security.jwt.utils;

import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.interfaces.Claim;

import java.util.*;

class ClaimsAdapter {

    private JWTCreator.Builder builder;

    private Set<String> keysCache = new HashSet<>();

    ClaimsAdapter(JWTCreator.Builder builder) {
        this.builder = builder;
    }

    ClaimsAdapter putAll(Map<String, Claim> claims) {
        for (Map.Entry<String, Claim> entry : claims.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
        return this;
    }

    ClaimsAdapter put(String key, Claim claim) {
        Object[] asArray = claim.asArray(Object.class);
        if (asArray == null) {
            return put(key, claim.as(Object.class));
        } else if (asArray.length > 0) {
            return put(key, claim.asArray(findElementType(asArray)));
        } else {
            return put(key, new String[0]);
        }
    }

    private Class<?> findElementType(Object[] asArray) {
        Object first = asArray[0];
        if (first instanceof String) {
            return String.class;
        } else if (first instanceof Integer) {
            return Integer.class;
        } else if (first instanceof Long) {
            return Long.class;
        } else {
            throw new IllegalArgumentException("Cannot handle value " + Arrays.toString(asArray) + " of type " + first.getClass());
        }
    }

    ClaimsAdapter put(String key, Object value) {
        keysCache.add(key);

        if (value instanceof String) {
            builder.withClaim(key, (String) value);
        } else if (value instanceof Integer) {
            builder.withClaim(key, (Integer) value);
        } else if (value instanceof Boolean) {
            builder.withClaim(key, (Boolean) value);
        } else if (value instanceof Long) {
            builder.withClaim(key, (Long) value);
        } else if (value instanceof Date) {
            builder.withClaim(key, (Date) value);
        } else if (value instanceof Double) {
            builder.withClaim(key, (Double) value);
        } else if (value instanceof String[]) {
            builder.withArrayClaim(key, (String[]) value);
        } else if (value instanceof Integer[]) {
            builder.withArrayClaim(key, (Integer[]) value);
        } else if (value instanceof Long[]) {
            builder.withArrayClaim(key, (Long[]) value);
        } else {
            throw new IllegalArgumentException("Cannot handle value " + value + "of type " + value.getClass());
        }

        return this;
    }

    boolean containsKey(String key) {
        return keysCache.contains(key);
    }
}
