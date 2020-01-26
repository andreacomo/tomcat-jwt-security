package it.cosenonjaviste.security.jwt.testutils;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyStores {

    private static final Log LOG = LogFactory.getLog(KeyStores.class);

    public static final String KEYSTORE = "keystore.jks";

    public static final String KEYSTORE_PASSWORD = "jwtpass";

    public static final String KEY_ID = "jwt";

    private KeyStores() {
        // prevent instance
    }

    public static RSAKeyProvider retrieveKey() {
        try {
            KeyStore keyStore = get();

            return new RSAKeyProvider() {
                @Override
                public RSAPublicKey getPublicKeyById(String keyId) {
                    try {
                        return (RSAPublicKey) keyStore.getCertificate(getPrivateKeyId()).getPublicKey();
                    } catch (KeyStoreException e) {
                        throw new RuntimeException(e);
                    }
                }

                @Override
                public RSAPrivateKey getPrivateKey() {
                    try {
                        return (RSAPrivateKey) keyStore.getKey(getPrivateKeyId(), KEYSTORE_PASSWORD.toCharArray());
                    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                        throw new RuntimeException(e);
                    }
                }

                @Override
                public String getPrivateKeyId() {
                    return KEY_ID;
                }
            };
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    public static KeyStore get() {
        try (InputStream in = KeyStores.class.getClassLoader().getResourceAsStream(KEYSTORE)) {
            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in, KEYSTORE_PASSWORD.toCharArray());

            return keyStore;
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }
}
