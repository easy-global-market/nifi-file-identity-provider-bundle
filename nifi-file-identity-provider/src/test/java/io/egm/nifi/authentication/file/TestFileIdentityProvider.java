/*
 * Copyright 2016 BatchIQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.egm.nifi.authentication.file;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.nifi.authentication.AuthenticationResponse;
import org.apache.nifi.authentication.LoginCredentials;
import org.apache.nifi.authentication.LoginIdentityProviderConfigurationContext;
import org.apache.nifi.authentication.LoginIdentityProviderInitializationContext;
import org.apache.nifi.authentication.LoginIdentityProviderLookup;
import org.apache.nifi.authentication.exception.IdentityAccessException;
import org.apache.nifi.authentication.exception.InvalidLoginCredentialsException;
import org.apache.nifi.authentication.exception.ProviderCreationException;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;


public class TestFileIdentityProvider {

    private static final String IDENTIFIER = "test-credentials-config";
    private static final String TEST_PROVIDER_ID = "test-provider";
    private static final String FIVE_MINUTES = "5 minutes";
    private static final String TEST_CREDENTIALS_FILE = "src/test/resources/test_credentials.xml";
    private static final String TEST_INVALID_CREDENTIALS_FILE = "src/test/resources/test_credentials_invalid.xml";


    @Test
    public void testConfigurationCredentialsFile() throws Exception {
        final Map<String, String> configProperties = new HashMap<String, String>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        final FileIdentityProvider provider = new FileIdentityProvider();
        provider.onConfigured(configContext);

        assertEquals(TEST_CREDENTIALS_FILE, provider.getCredentialsFilePath());
        assertEquals(5 * 60 * 1000, provider.getExpirationPeriod());
    }

    @Test
    public void testConfigurationMissingFile() {
        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        final FileIdentityProvider provider = new FileIdentityProvider();
        assertThrows(ProviderCreationException.class, () ->
                provider.onConfigured(configContext)
        );
    }

    @Test
    public void testConfigurationEmptyFile() {
        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, "");
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        final FileIdentityProvider provider = new FileIdentityProvider();
        assertThrows(ProviderCreationException.class, () ->
                provider.onConfigured(configContext)
        );
    }

    @Test
    public void testConfigurationMissingFileLogsWarning() {
        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final String missingFilePath = "no/such/file";
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, missingFilePath);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        Logger fileIdentityProviderLogger = (Logger) LoggerFactory.getLogger(FileIdentityProvider.class);
        ListAppender<ILoggingEvent> testAppender = new ListAppender<>();
        testAppender.setName("Test");
        testAppender.start();
        fileIdentityProviderLogger.addAppender(testAppender);
        final FileIdentityProvider provider = new FileIdentityProvider();

        provider.onConfigured(configContext);

        boolean fileMessageFound = false;
        for (ILoggingEvent event : testAppender.list) {
            String message = event.getFormattedMessage();
            if (message.contains(missingFilePath) && event.getLevel() == Level.WARN) {
                fileMessageFound = true;
                break;
            }
        }
        assertTrue(fileMessageFound);
    }

    @Test
    public void testConfigurationMissingExpiration() {
        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        final FileIdentityProvider provider = new FileIdentityProvider();
        assertThrows(ProviderCreationException.class, () ->
                provider.onConfigured(configContext)
        );
    }

    @Test
    public void testConfigurationMalformedExpiration() {
        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        final String badExpirationPeriod = "3 eternities";
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, badExpirationPeriod);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        final FileIdentityProvider provider = new FileIdentityProvider();
        assertThrows(ProviderCreationException.class, () ->
                provider.onConfigured(configContext)
        );
    }

    @Test
    public void testUserNotInFileThrows() {
        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        final FileIdentityProvider provider = new FileIdentityProvider();
        provider.onConfigured(configContext);

        final LoginCredentials loginCredentials = new LoginCredentials("BogusUser", "BogusPassword");
        assertThrows(InvalidLoginCredentialsException.class, () ->
                provider.authenticate(loginCredentials)
        );
    }

    @Test
    public void testValidLoginWorks() {
        final FileIdentityProvider provider = new FileIdentityProvider();
        final MockLoginIdentityProviderInitializationContext initContext =
                new MockLoginIdentityProviderInitializationContext(TEST_PROVIDER_ID);
        provider.initialize(initContext);

        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        provider.onConfigured(configContext);

        final LoginCredentials loginCredentials = new LoginCredentials("user2", "CantGuessMe");
        final AuthenticationResponse authResponse = provider.authenticate(loginCredentials);
        assertEquals("user2", authResponse.getUsername());
        assertEquals("FileIdentityProvider", authResponse.getIssuer());
        assertEquals("user2", authResponse.getIdentity());
    }

    @Test
    public void testValidLoginIsCaseInsensitive() {
        final FileIdentityProvider provider = new FileIdentityProvider();
        final MockLoginIdentityProviderInitializationContext initContext =
                new MockLoginIdentityProviderInitializationContext(TEST_PROVIDER_ID);
        provider.initialize(initContext);

        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        provider.onConfigured(configContext);

        final LoginCredentials loginCredentialsLowercase = new LoginCredentials("user2", "CantGuessMe");
        final AuthenticationResponse authResponseLowercase = provider.authenticate(loginCredentialsLowercase);
        final LoginCredentials loginCredentialsUppercase = new LoginCredentials("USER2", "CantGuessMe");
        final AuthenticationResponse authResponseUppercase = provider.authenticate(loginCredentialsUppercase);
    }

    @Test
    public void testValidUserWrongPasswordThrows() {
        final FileIdentityProvider provider = new FileIdentityProvider();
        final MockLoginIdentityProviderInitializationContext initContext =
                new MockLoginIdentityProviderInitializationContext(TEST_PROVIDER_ID);
        provider.initialize(initContext);

        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_CREDENTIALS_FILE);
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        provider.onConfigured(configContext);

        final LoginCredentials loginCredentials = new LoginCredentials("user2", "WrongPassword");
        assertThrows(InvalidLoginCredentialsException.class, () ->
                provider.authenticate(loginCredentials)
        );
    }

    @Test
    public void testLoginUsersFileInvalidThrows() {
        final FileIdentityProvider provider = new FileIdentityProvider();
        final MockLoginIdentityProviderInitializationContext initContext =
                new MockLoginIdentityProviderInitializationContext(TEST_PROVIDER_ID);
        provider.initialize(initContext);

        final Map<String, String> configProperties = new HashMap<>();
        configProperties.put(FileIdentityProvider.PROPERTY_CREDENTIALS_FILE, TEST_INVALID_CREDENTIALS_FILE);
        configProperties.put(FileIdentityProvider.PROPERTY_EXPIRATION_PERIOD, FIVE_MINUTES);
        final LoginIdentityProviderConfigurationContext configContext =
                new MockLoginIdentityProviderConfigurationContext(IDENTIFIER, configProperties);
        provider.onConfigured(configContext);

        final LoginCredentials loginCredentials = new LoginCredentials("user1", "SomePassword");
        assertThrows(IdentityAccessException.class, () ->
                provider.authenticate(loginCredentials)
        );
    }

    class MockLoginIdentityProviderConfigurationContext implements LoginIdentityProviderConfigurationContext {
        private final String identifier;
        private final Map<String, String> properties;

        public MockLoginIdentityProviderConfigurationContext(String identifier, Map<String, String> properties) {
            this.identifier = identifier;
            this.properties = properties;
        }

        @Override
        public String getIdentifier() {
            return identifier;
        }

        @Override
        public Map<String, String> getProperties() {
            return Collections.unmodifiableMap(properties);
        }

        @Override
        public String getProperty(String property) {
            return properties.get(property);
        }
    }

    class MockLoginIdentityProviderInitializationContext implements LoginIdentityProviderInitializationContext {

        private final String identifier;

        public MockLoginIdentityProviderInitializationContext(String identifier) {
            this.identifier = identifier;
        }
        @Override
        public String getIdentifier() {
            return identifier;
        }

        @Override
        public LoginIdentityProviderLookup getAuthorityProviderLookup() {
            throw new UnsupportedOperationException();
        }
    }
}
