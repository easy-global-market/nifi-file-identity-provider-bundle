# NiFi File Identity Provider
An identity provider for [Apache NiFi](https://nifi.apache.org/) 1.21.0 or later, providing authentication of users
based on username/password credentials.  Credentials are stored in a local file with Bcrypt-hashed passwords.
This may be suitable for environments without LDAP or Kerberos, or when X.509 client certificates are impractical.

Note: it was previously developed and published on GitHub (under the APL license) by a company called BatchIQ that
seems to no longer exist. An archived fork was still existing somewhere on GitHub. This project is thus a revival of
this archive.

## Use

To install and use this provider you must complete the following steps:

1. Build the provider NAR file
2. Deploy the provider NAR file to your NiFi installation
3. Configure NiFi for HTTPS
4. Configure the File Authorization Provider `login-identity-providers.xml`
5. Configure identity of the File Authorization Provider in `nifi.properties`
6. Add users and their Bcrypt-hashed passwords in `login-credentials.xml`

### Build

Build this package with:
```
mvn clean package
```

### Deploy

Deploy the resulting NAR file from the `nifi-file-identity-provider-nar/target` directory (NAR file will look 
like `nifi-file-identity-provider-nar-1.0.0.nar`) into the `lib` directory of your NiFi installation.

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

Please see the [NiFi Administration Guide](https://nifi.apache.org/docs/nifi-docs/html/administration-guide.html) for more information on secure access configurations.

### Configure the File Identity Provider

Add the following Login Identity Provider in `login-identity-providers.xml`:

```
<provider>
    <identifier>file-identity-provider</identifier>
    <class>io.egm.nifi.authentication.file.FileIdentityProvider</class>
    <property name="Credentials File">conf/login-credentials.xml</property>
    <property name="Authentication Expiration">12 hours</property>
</provider>
```

### Configure NiFi to Use the File Identity Provider

After the provider itself is configured, reference it in `nifi.properties`.

```
nifi.security.user.login.identity.provider=file-identity-provider
nifi.security.user.authorizer=managed-authorizer
```

### Disable the Single User Authorizer

In `conf/authorizers.xml`, comment out the `single-user-authorizer` configuration at the bottom of the file.

### Initialize User Credentials

User credentials must be initialized in the credentials store file `login-credentials.xml`.

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

#### Generate Bcrypt-hashed Passwords

Any tool capable of generating Bcyrpt type 2a hashed passwords may be used.  This package includes a simple command-line
utility in the `PasswordHasherCLI` class (see below).  Additional known compatible tools and APIs include:

* Spring Security's [BCryptPasswordEncoder](https://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.html) class
* Python package [bcrypt](https://pypi.python.org/pypi/bcrypt/2.0.0)
* Online [Bcrypt Generator](https://appdevtools.com/bcrypt-generator)

#### Create and give admin rights to the first user

Add an entry in the previously created `login-credentials.xml` for the first user, for instance:

```
<credentials>
    <user name="nifi-admin" passwordHash="$2a$10$POV6w2nzonBWOyB4evQoUO8gG9oYABn2eWd/GdZ/RHceJiqDNYWGm" />
</credentials>
```

Then configure it as the initial admin of the NiFi instance in `authorizers.xml`. This has to be done in:
* Initial User Identity 1 property of the `userGroupProvider` section
* Initial Admin Identity property of the `accessPolicyProvider` section

### Start NiFi

Start NiFi and connect using the credentials configured for the initial admin user.

### CLI Tool

This package includes a command-line tool for simple operations on users and passwords.  Use of this tool is not required,
it is possible to administer users with a text editor and any tool capable of generating Bcrypt 2a hashes.

The JAR file `nifi-file-identity-provider-1.21.0-cli.jar` is output in the nifi-file-identity-provider/target directory.

Add a user, you will be prompted for a password:
```
>java -jar nifi-file-identity-provider-1.21.0-cli.jar add conf/login-credentials.xml jane
Password for jane: ****
Added user jane
```

Reset password, you will be prompted for password:
```
>java -jar nifi-file-identity-provider-1.21.0-cli.jar reset conf/login-credentials.xml jane
New Password for jane:
Password reset for user jane
```

List users
```
>java -jar nifi-file-identity-provider-1.21.0-cli.jar list conf/login-credentials.xml
john
jane
frank
```

Delete user
```
>java -jar nifi-file-identity-provider-1.21.0-cli.jar remove conf/login-credentials.xml frank
Removed user frank
```

## License

Apache License 2.0
