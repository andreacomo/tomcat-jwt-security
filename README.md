[![Build Status](https://travis-ci.org/andreacomo/tomcat-jwt-security.svg?branch=master)](https://travis-ci.org/andreacomo/tomcat-jwt-security)
[![Released Version](https://img.shields.io/maven-central/v/it.cosenonjaviste/tomcat-jwt-security.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22it.cosenonjaviste%22%20a%3A%22tomcat-jwt-security%22)

# tomcat-jwt-security
This project aims to bring JWT token authentication capabilities into **Tomcat 8**, implementing an authentication filter as a Tomcat Valve. JWT manipulation is based on [java-jwt](https://github.com/auth0/java-jwt) project.

For Tomcat 7, please use [version 1.1.0](https://github.com/andreacomo/tomcat-jwt-security/releases/tag/tomcat-jwt-security-1.1.0) or clone [tomcat-7 branch](https://github.com/andreacomo/tomcat-jwt-security/tree/tomcat-7).

Valve-based authentication is supposed to work along with Java **standard security constraints** placed in your *web.xml* file and will leave your server **stateless**: with a JWT token you can keep your Tomcat *free of http session*.

From version 3.0.0, several improvements have been made (with *many breaking changes* - please refers to release notes).
Now you can take advantages of signing and verifying your JWT tokens with:

 * **HMAC** algorithms, providing a **secret text** (the legacy approach, available since versions 2.x.x)
 * **RSA** algorithms, providing a **keystore with a public key** 
 * **OpenID Connect** (OIDC) JWT ID Tokens are now validated against **public keys** downloaded from a valid JWKS uri, provided by your OIDC Identity Provider

# Getting started
You can download artifacts (1.a) or build the project on your own (1.b), then configure Tomcat and your security constraints in your project to enable authentication system. 

Finally, read how to create tokens in your app, if you sign your tokens with HMAC or RSA.

## 1.a Download artifacts
Download artifacts (project and dependencies), from Maven Central Repo, when using HMAC (`HmacJwtTokenValve`) or RSA (`RsaJwtTokenValve`) valves:
* [tomcat-jwt-security-3.0.0.jar](https://repo1.maven.org/maven2/it/cosenonjaviste/tomcat-jwt-security/3.0.0/tomcat-jwt-security-3.0.0.jar)
  * [java-jwt-3.9.0.jar](https://repo1.maven.org/maven2/com/auth0/java-jwt/3.9.0/java-jwt-3.9.0.jar)
    * [jackson-databind-2.10.1.jar](https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.10.1/jackson-databind-2.10.1.jar) (this may *cause problems* with [some Tomcat version](https://stackoverflow.com/questions/23541532/org-apache-tomcat-util-bcel-classfile-classformatexception-invalid-byte-tag-in))
      * [jackson-core-2.10.1.jar](https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.10.1/jackson-core-2.10.1.jar)
      * [jackson-annotations-2.10.1.jar](https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.10.1/jackson-annotations-2.10.1.jar)
    * [commons-codec-1.12.jar](https://repo1.maven.org/maven2/commons-codec/commons-codec/1.12/commons-codec-1.12.jar)
    
If you need to use OpenID Connect valve (`OidcJwtTokenValve`), you need further dependencies:

  * [jwks-rsa-0.9.0.jar](https://repo1.maven.org/maven2/com/auth0/jwks-rsa/0.9.0/jwks-rsa-0.9.0.jar)
    * [guava-27.1-jre.jar](https://repo1.maven.org/maven2/com/google/guava/guava/27.1-jre/guava-27.1-jre.jar)
      * [failureaccess-1.0.1.jar](https://repo1.maven.org/maven2/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar)

Place dependencies into *TOMCAT_HOME/lib* directory

## 1.b Build project
You can build with a simple
```
mvn install
```
and grab artifacts from *target/to-deploy* folder. Copy generated artifacts into *TOMCAT_HOME/lib* directory

## 2. Register Valve
Now it's time to register the valve. According to your signing method or token provider, from version 3.0.0 you can choose proper valve, according to your scenario:

 * `HmacJwtTokenValve`: to be used when tokens are signed with **HMAC**, based on a **pre-shared secret text**.
   Configurable parameters are:
     
     | Parameter | Type | Mandatory | Default | Description |
     | --- | --- | --- | --- | --- |
     | `secret` | String | Y | | Passphrase used to verify the token sign. Since HMAC is a sync algorithm, it's also used to recreate and sign the token when `updateExpire` is `true` | 
     | `updateExpire` | Boolean | N | `false` | Each request produces a new token in `X-Auth` response header with a delayed expire time. This simulates default Servlet HTTP Session behaviour |
     | `cookieName` | String | N | | Name of the cookie containing JWT token instead of HTTP headers |
     | `customUserIdClaim` | String | N | `userId` | Claim that identify the user id |
     | `customRolesClaim`| String | N | `roles` | Claim that identify user capabilities |
     
   Example 
   
   ```xml
   <Valve className="it.cosenonjaviste.security.jwt.valves.HmacJwtTokenValve" 
         secret="my super secret password"
         updateExpire="true"
         cookieName="auth" />
   ```
     
 * `RsaJwtTokenValve`: to be used when tokens are signed with **RSA**, based on certificates pairs.
    Configurable parameters are:
        
      | Parameter | Type | Mandatory | Default | Description |
      | --- | --- | --- | --- | --- |
      | `keystorePath` | String | Y* | | Keystore file system path |
      | `keystorePassword` | String | Y* | | Keystore password |
      | `keyPairsAlias`| String | N | the first one in keystore | Keys pairs alias in keystore. If not provided, the first *public key* in keystore will be used |
      | `keyStore` | Keystore | Y** | | Keystore instance (useful when keystore is in classpath and is java-based configured) |
      | `cookieName` | String | N | | Name of the cookie containing JWT token instead of HTTP headers |
      | `customUserIdClaim` | String | N | `userId` | Claim that identify the user id |
      | `customRolesClaim`| String | N | `roles` | Claim that identify user capabilities |
      
      Mandatory groups (\*) and (\*\*) are mutually exclusive: `keyStore` param *takes precedence*.
        
      Example 
      
      ```xml
      <Valve className="it.cosenonjaviste.security.jwt.valves.RsaJwtTokenValve" 
                 keystorePath="/etc/keystores/keystore.jks"
                 keystorePassword="ks_password"
                 customUserIdClaim="sub" 
                 customRolesClaim="authorities" />
      ```
   
 * `OidcJwtTokenValve`: to be used when tokens are provided by an OpenID Connect Identity Provider (OIDC IDP).
   Configurable parameters are:
     
     | Parameter | Type | Mandatory | Default | Description |
     | --- | --- | --- | --- | --- |
     | `issuerUrl` | URL | Y | | URL where to retrieve IDP keys: it's the value of `jwks_uri` key of `.well-known/openid-configuration` endpoint provided by your IDP  | 
     | `supportedAudiences` | String | N | | Allowed `aud` values in token. If `supportedAudiences` is not set, **no validation** is performed |
     | `expiresIn` | Integer | N | 60 | Cache duration of keys before recontact IDP for new keys |
     | `timeUnit` | TimeUnit | N | MINUTES | Cache time unit. Allowed values are: `NANOSECONDS`, `MICROSECONDS`, `MILLISECONDS`, `SECONDS`, `MINUTES`, `HOURS`, `DAYS` |
     | `customUserIdClaim` | String | N | `sub` | Claim that identify the user id |
     | `customRolesClaim`| String | N | `authorities` | Claim that identify user capabilities |
     
   Example 
   
   ```xml
   <Valve className="it.cosenonjaviste.security.jwt.valves.OidcJwtTokenValve" 
             issuerUrl="http://idp.example.com/openid-connect/certs"
             expiresIn="30"
             timeUnit="MINUTES" />
   ```
    
Valves can be configured in Tomcat in:
* `server.xml` for registering valve at **Engine** or **Host** level
* `context.xml` for registering valve at application **Context** level

In order for the valve to work, a **realm should be provided**. An example for a JDBCRealm can be found on [a post on TheJavaGeek](http://www.thejavageek.com/2013/07/07/configure-jdbcrealm-jaas-for-mysql-and-tomcat-7-with-form-based-authentication/)

## 3. Enable `security-contraint`
All these valves check if requested url is under **security constraints**. So, valve behaviour will be activated only if your application *web.xml* file contains something like this:

```xml
<security-constraint>
  <web-resource-collection>
		<web-resource-name>api</web-resource-name>
		<url-pattern>/api/*</url-pattern>
	</web-resource-collection>
	<auth-constraint>
		<role-name>*</role-name>
	</auth-constraint>
</security-constraint>
<security-role>
	<role-name>admin</role-name>
</security-role>
<security-role>
	<role-name>devop</role-name>
</security-role>
<login-config>
  <auth-method>BASIC</auth-method>
  <realm-name>MyAppRealm</realm-name>
</login-config>
```
Please note `<auth-method>` tag: is set to **BASIC** in order to *avoid HTTP Session creation on server side*. If you omit `<auth-method>` or use another authentication method, Tomcat will create an HTTP session for you, but we *want our server stateless*!

Now your server is ready. How to generate a token from your app?

# How to integrate in your project

## HMAC and RSA
`HmacJwtTokenValve` and `RsaJwtTokenValve` inherits from an abstract `JwtTokenValve` that is supposed to search for authentication token according to these priorities:
 * in `X-Auth` *header param* 
 * in `Authorization` *header param* with token preceded by `Bearer ` type 
 * in `access_token` *query parameter* (useful for downloading a file for example)
 * in a `cookie`: cookie's name is set by valve parameter *cookieName*

Your login controller **must** create a token in order to be validated: *each following request* to protected application must contain one of the authentication methods above.

You can use classes provided by *[java-jwt project](https://github.com/auth0/java-jwt)* (recommended), for example:

```java
String token = JWT.create()
       .withSubject(securityContext.getUserPrincipal().getName())
       .withArrayClaim("authorities", new String[]{"admin", "devop"})
       .withIssuedAt(new Date())
       .sign(Algorithm.HMAC256("my super secret password"));

...

response.addHeader(JwtConstants.AUTH_HEADER, token);

```

or our utility classes such as `JwtTokenBuilder` or `JwtConstants` (legacy): *tomcat-jwt-security* is also available on Maven Central. 
You can include it in your project as **provided** dependency (because is in your TOMCAT_HOME/lib folder already!):

```xml
<dependency>
	<groupId>it.cosenonjaviste</groupId>
	<artifactId>tomcat-jwt-security</artifactId>
	<version>3.0.0</version>
	<scope>provided</scope>
</dependency>
```

And use it like this in your *login controller*:
```java
String token = JwtTokenBuilder.create(Algorithm.HMAC256("my super secret password"))
                            .userId(securityContext.getUserPrincipal().getName())
                            .roles(Arrays.asList("admin", "devop"))
                            .expirySecs(1800)
                            .build();

...

response.addHeader(JwtConstants.AUTH_HEADER, token);
```

## OpenID Connect
In case of `OidcJwtTokenValve`, you *don't need a login controller*: just set your JWT token in every HTTP header `Authorization`, preceded by `Bearer`.

Enjoy now your stateless security system on Tomcat!!

# JWT Valve and Spring Boot
If you want to use this Valve with **Embedded Tomcat** provided by *Spring Boot*, forget about `web.xml` or `context.xml`!
Just include as **Maven dependency** in `compile` scope and implement a `EmbeddedServletContainerCustomizer` like this:

```java
@Configuration
public class TomcatJwtSecurityConfig implements EmbeddedServletContainerCustomizer {

    @Override
    public void customize(ConfigurableEmbeddedServletContainer container) {
        if (container instanceof TomcatEmbeddedServletContainerFactory) {
            TomcatEmbeddedServletContainerFactory factory = (TomcatEmbeddedServletContainerFactory) container;
            factory.addContextValves(newJwtTokenValve());
            factory.addContextValves(new BasicAuthenticator());
            factory.addContextCustomizers(context -> {
                context.setRealm(newJdbcRealm());

                // replace web.xml entries
                context.addConstraint(unsecured());
                context.addConstraint(secured());
                context.addSecurityRole("admin");
                context.addSecurityRole("devop");
            });
        }
    }

    private SecurityConstraint unsecured() {
        SecurityCollection collection = new SecurityCollection("login", "login");
        collection.addPattern("/api/login");

        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.addCollection(collection);

        return securityConstraint;
    }

    private SecurityConstraint secured() {
        SecurityCollection collection = new SecurityCollection("api", "api");
        collection.addPattern("/api/*");

        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.addAuthRole("*");
        securityConstraint.setAuthConstraint(true);
        securityConstraint.addCollection(collection);

        return securityConstraint;
    }

    private HmacJwtProvider newJwtTokenValve() {
        HmacJwtProvider valve = new HmacJwtProvider();
        valve.setSecret("my-secret");
        valve.setUpdateExpire(true);
        return valve;
    }
    
    private Realm newJdbcRealm() {
        // your favourite realm 
    }
}
```

Some notes:
* this is a programmatic version of `web.xml` configuration (and `context.xml`)
* `BasicAuthenticator` is required because `JwtTokenValve` **is not an authenticator**: 
`BasicAuthenticator` mainly delegates login phase to registered Realm in *Tomcat Context*.
