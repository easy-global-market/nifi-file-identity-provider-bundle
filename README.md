[![Build Status](https://travis-ci.org/BatchIQ/nifi-file-identity-provider-bundle.svg)](https://travis-ci.org/BatchIQ/nifi-file-identity-provider-bundle)

# NiFi File Identity Provider (Archived!!)
An identity provider for [Apache NiFi](https://nifi.apache.org/) 1.0.0 or later, providing authentication of users
based on username/password credentials.  Credentials are stored in a local file with Bcrypt-hashed passwords.
This may be suitable for environments without LDAP or Kerberos, or when X.509 client certificates are impractical.

## Use
To install and use this provider you must complete the following steps:

1. Build the provider NAR file
2. Deploy the provider NAR file to your NiFi installation
3. Configure NiFi for HTTPS
4. Configure the File Authorization Provider `login-identity-providers.xml`
5. Identity of the File Authorization Provider must be set in `nifi.properties`
6. Users and their Bcrypt-hashed passwords must be added to `login-credentials.xml`

### Build
Build this package with:
```
mvn clean package
```
You will need to deploy the resulting NAR file from the `nifi-file-identity-provider-nar/target` directory
(NAR file will look like `nifi-file-identity-provider-nar-1.0.0.nar`).

### Deploy
The provider NAR file should be deployed to your NiFi's `lib` directory.

### Configure NiFi for HTTPS
NiFi must be configured for HTTPS, including at least the following settings in `nifi.properties`:
* nifi.web.https.port
* nifi.security.keystore
* nifi.security.keystoreType
* nifi.security.keystorePasswd
* nifi.security.keyPasswd
* nifi.security.truststore
* nifi.security.truststoreType
* nifi.security.truststorePasswd

Please see the [NiFi Administration Guide](https://nifi.apache.org/docs/nifi-docs/html/administration-guide.html)
for more information on secure access configurations.

### Configure the File Identity Provider
The following Login Identity Provider configuration should be added to `login-identity-providers.xml`:
```
<provider>
    <identifier>file-identity-provider</identifier>
    <class>io.egm.nifi.authentication.file.FileIdentityProvider</class>
    <property name="Credentials File">conf/login-credentials.xml</property>
    <property name="Authentication Expiration">12 hours</property>
</provider>
```

### Configure NiFi to Use the File Identity Provider
After the provider itself is configured, reference this provider in `nifi.properties`.

```
nifi.security.user.login.identity.provider=file-identity-provider
nifi.security.user.authorizer=managed-authorizer
```

### Disable the Single User Authorizer
In `conf/authorizers.xml`, comment out the `single-user-authorizer` configuration at the bottom of the file.

### Initialize User Credentials
User credentials must be initialized in the credentials store file `conf/login-credentials.xml`.
This is an XML file with the following format:

```
<!--
    This file contains users and their hashed passwords. Please see the
    io.egm.nifi.authentication.file.CredentialsStore for details.

    User Format:
    name - must match the "identity" in authorized-users.xml
    passwordHash - hashed passwords in Bcrypt 2a format / 10 rounds, looks
      like "$2a$10$24wB0UAUsRbOXz4KRZ5KlenzcEddnhIyXMyPkpTnS/29Tt12jfJJW"
-->
<credentials>
    <!--
    <user name="admin" passwordHash="(reset to populate)" />
    -->
</credentials>
```

#### Generating Bcrypt-hashed Passwords
Any tool capable of generating Bcyrpt type 2a hashed passwords may be used.  This package includes a simple command-line
utility in the `PasswordHasherCLI` class (see below).  Additional known compatible tools and APIs include:

* Spring Security's [BCryptPasswordEncoder](https://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.html) class
* Python package [bcrypt](https://pypi.python.org/pypi/bcrypt/2.0.0)
* Online [Bcrypt Generator](https://appdevtools.com/bcrypt-generator)

### CLI Tool
This package includes a command-line tool for simple operations on users and passwords.  Use of this tool is not required,
it is possible to administer users with a text editor and any tool capable of generating Bcrypt 2a hashes.

The JAR file `nifi-file-identity-provider-1.0.0-cli.jar` is output in the nifi-file-identity-provider/target directory.

Add a user, you will be prompted for a password:
```
>java -jar nifi-file-identity-provider-1.0.0-cli.jar add credentials.xml jane
Password for jane: ****
Added user jane
```

Reset password, you will be prompted for password:
```
>java -jar nifi-file-identity-provider-1.0.0-cli.jar reset credentials.xml jane
New Password for jane:
Password reset for user jane
```

List users
```
>java -jar nifi-file-identity-provider-1.0.0-cli.jar list credentials.xml
john
jane
frank
```

Delete user
```
>java -jar nifi-file-identity-provider-1.0.0-cli.jar remove credentials.xml frank
Removed user frank
```

## License
Apache License 2.0
