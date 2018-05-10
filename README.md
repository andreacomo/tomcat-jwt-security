[![Build Status](https://travis-ci.org/andreacomo/tomcat-jwt-security.svg?branch=master)](https://travis-ci.org/andreacomo/tomcat-jwt-security)

# tomcat-jwt-security
This project aims to bring JWT token authentication capabilities into **Tomcat 8**, implementing an authentication filter as a Tomcat valve, based on [java-jwt](https://github.com/auth0/java-jwt) project.

For Tomcat 7, please use [version 1.1.0](https://github.com/andreacomo/tomcat-jwt-security/releases/tag/tomcat-jwt-security-1.1.0) or clone [tomcat-7 branch](https://github.com/andreacomo/tomcat-jwt-security/tree/tomcat-7).

Valve-based authentication is supposed to work along with Java **standard security constraints** placed in your *web.xml* file and will leave your server **stateless**: with a JWT token you can keep your Tomcat free of http session.

# Getting started
You can download artifacts (1.a) or build the project on your own (1.b), then configure Tomcat and your security constraints in your project to enable authentication system. 

Finally, read how to create tokens in your app.

## 1.a Download artifacts
Download artifacts (project and dependencies) from Maven Central Repo
* [tomcat-jwt-security-2.0.0.jar](https://repo1.maven.org/maven2/it/cosenonjaviste/tomcat-jwt-security/2.0.0/tomcat-jwt-security-2.0.0.jar)
* [java-jwt-2.0.1.jar](https://repo1.maven.org/maven2/com/auth0/java-jwt/2.1.0/java-jwt-2.1.0.jar)

and place into *TOMCAT_HOME/lib* directory

## 1.b Build project
You can build with a simple
```
mvn install
```
and grab artifacts from *target/to-deploy* folder. Copy generated artifacts into *TOMCAT_HOME/lib* directory

## 2. Register Valve
Now register **`JwtTokenValve`** in Tomcat configuration file.
* use *server.xml* for registering valve at **Engine** or **Host** level (for SSO pourpose)
* use *context.xml* for registering valve at application **Context** level

```xml
<Valve className="it.cosenonjaviste.security.jwt.valves.JwtTokenValve" 
	  		 secret="my super secret password"
	  		 updateExpire="true" />
```

where:
* ***secret***: is secret passphrase for signing token
* ***updateExpire***: (default **false**) ***resends*** token to client on each response with expire time updated to last request

In order for the valve to work, a **realm shoul be provided**. An example for a JDBCRealm can be found on [a post on TheJavaGeek](http://www.thejavageek.com/2013/07/07/configure-jdbcrealm-jaas-for-mysql-and-tomcat-7-with-form-based-authentication/)

## 3. Enable `security-contraint`
**`JwtTokenValve`** checks if requested url is under **security contraints**. So, valve will activate only if your application *web.xml* file contains something like:

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
`JwtTokenValve` is supposed to search for authentication token according to these priorities:
 * in `X-Auth` *header param* 
 * in `Authorization` *header param* with token preceded by `Bearer ` type 
 * in `access_token` *query parameter* (useful for downloading a file for example)
Your login controller **must** create a token in order to be validated from this *valve*: *each following request* must contain `X-Auth` header with token value (or `Authorization: Bearer <token>` header or `access_token=<token>` query parameter).

You can use classes provided by *[java-jwt project](https://github.com/auth0/java-jwt)* or our utility classes such as `JwtTokenBuilder` or `JwtConstants`: this is why *tomcat-jwt-security* is also available on Maven Central. You can include it in your project as **provided** dependency (because is in your TOMCAT_HOME/lib folder already!):
```xml
<dependency>
	<groupId>it.cosenonjaviste</groupId>
	<artifactId>tomcat-jwt-security</artifactId>
	<version>2.1.0</version>
	<scope>provided</scope>
</dependency>
```

And use like this in your *login controller*:
```java
JwtTokenBuilder tokenBuilder = JwtTokenBuilder.create("my super secret password");
String token = tokenBuilder.userId(securityContext.getUserPrincipal().getName())
                            .roles(Arrays.asList("admin", "devop"))
                            .expirySecs(1800)
                            .build();

...

response.addHeader(JwtConstants.AUTH_HEADER, token);  
```

Enjoy your stateless security system on Tomcat!!

# JWT Valve and Spring Boot
If you want to use this Valve with **Embedded Tomcat** provided by *Spring Boot*, forget about `web.xml` or `context.xml`!
Just implement a `EmbeddedServletContainerCustomizer` like this:

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

    private JwtTokenValve newJwtTokenValve() {
        JwtTokenValve valve = new JwtTokenValve();
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