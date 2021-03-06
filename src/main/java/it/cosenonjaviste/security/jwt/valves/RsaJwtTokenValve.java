package it.cosenonjaviste.security.jwt.valves;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import it.cosenonjaviste.security.jwt.exceptions.ValveInitializationException;
import it.cosenonjaviste.security.jwt.utils.Preconditions;
import it.cosenonjaviste.security.jwt.utils.verifiers.JwtTokenVerifier;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RsaJwtTokenValve extends JwtTokenValve {

    private static final Log LOG = LogFactory.getLog(RsaJwtTokenValve.class);

    private String keystorePath;

    private String keystorePassword;

    private String keyPairsAlias;

    private KeyStore keyStore;

    @Override
    protected JwtTokenVerifier createTokenVerifier(String customUserIdClaim, String customRolesClaim) {
        try {
            KeyStore keyStore = getKeyStore();
            String alias = keyPairsAlias == null ? keyStore.aliases().nextElement() : keyPairsAlias;
            Certificate certificate = keyStore.getCertificate(alias);
            Preconditions.checkValveInit(certificate != null, "Alias '" + alias + "' not found in keystore");

            final PublicKey publicKey = certificate.getPublicKey();

            return JwtTokenVerifier.create(newRsaKeyProvider((RSAPublicKey) publicKey), customUserIdClaim, customRolesClaim);
        } catch (KeyStoreException e) {
            LOG.error(e.getMessage(), e);
            throw new ValveInitializationException(e.getMessage(), e);
        }
    }

    private RSAKeyProvider newRsaKeyProvider(RSAPublicKey publicKey) {
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return publicKey;
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

    /**
     * If keystore is set from external call to {@link #setKeyStore}, keystorePath and keystorePassword will be ignored
     *
     * @return {@link KeyStore} instance
     */
    private KeyStore getKeyStore() {
        if (keyStore == null) {
            keyStore = loadKeyStore();
        }
        return keyStore;
    }

    private KeyStore loadKeyStore() {
        try (InputStream in = new FileInputStream(keystorePath)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in, keystorePassword.toCharArray());

            return keyStore;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            LOG.error(e.getMessage(), e);
            throw new ValveInitializationException(e.getMessage(), e);
        }
    }

    public void setKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public void setKeyPairsAlias(String keyPairsAlias) {
        this.keyPairsAlias = keyPairsAlias;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }
}
