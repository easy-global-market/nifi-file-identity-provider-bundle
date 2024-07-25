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

import io.egm.nifi.authentication.file.generated.UserCredentials;
import io.egm.nifi.authentication.file.generated.UserCredentialsList;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

import javax.xml.bind.UnmarshalException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InvalidObjectException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


public class TestCredentialsStore {

    private static final String TEST_CREDENTIALS_FILE = "src/test/resources/test_credentials.xml";
    private static final String TEST_INVALID_CREDENTIALS_FILE = "src/test/resources/test_credentials_invalid.xml";
    private static final String TEST_DUPLICATE_USER_CREDENTIALS_FILE = "src/test/resources/test_credentials_duplicate.xml";
    private static final String TEST_READ_WRITE_CREDENTIALS_FILE = "src/test/resources/test_read_write_credentials.xml";

    @Test
    public void testConfigFileNotFound() {
        assertThrows(FileNotFoundException.class, () ->
                CredentialsStore.loadCredentialsList("NonExistingFile.xml")
        );
    }

    @Test
    public void testLoadCredentialsFile() throws Exception {
        final UserCredentialsList credentials = CredentialsStore.loadCredentialsList(TEST_CREDENTIALS_FILE);
        final List<UserCredentials> users = credentials.getUser();
        assertEquals(2, users.size());

        final UserCredentials userCred = users.get(0);
        assertEquals("user1", userCred.getName());
        assertEquals("fakePasswordHash", userCred.getPasswordHash());
    }

    @Test
    public void testLoadInvalidCredentialsFileMessaging() throws Exception {
        try {
            CredentialsStore.loadCredentialsList(TEST_INVALID_CREDENTIALS_FILE);
        } catch (UnmarshalException unmarshalEx) {
            String exceptionMessage = unmarshalEx.toString();
            assertTrue(exceptionMessage.contains("invalid_credentials"));
            assertTrue(exceptionMessage.contains(TEST_INVALID_CREDENTIALS_FILE));
        }
    }

    @Test
    public void testLoadInvalidDuplicateUserCredentialsFileMessaging() {
        try {
            CredentialsStore.loadCredentialsList(TEST_DUPLICATE_USER_CREDENTIALS_FILE);
            fail("Duplicate user in credentials file should throw an exception");
        } catch (UnmarshalException unmarshalEx) {
            String exceptionMessage = unmarshalEx.toString();
            assertTrue(exceptionMessage.contains("unique"));
            assertTrue(exceptionMessage.contains(TEST_DUPLICATE_USER_CREDENTIALS_FILE));
        } catch (Exception ex) {
            fail("Should have thrown an UnmarshalException");
        }
    }

    @Test
    public void testReadWriteCredsFile() throws Exception {
        File tempFile = File.createTempFile("testReadWriteCredsFile_actual", "xml");
        final UserCredentialsList credentials = CredentialsStore.loadCredentialsList(TEST_READ_WRITE_CREDENTIALS_FILE);
        CredentialsStore.saveCredentialsList(credentials, tempFile);
        String actualContent = FileUtils.readFileToString(tempFile, StandardCharsets.UTF_8);
        File expectedFile = new File(TEST_READ_WRITE_CREDENTIALS_FILE);
        String expectedContent = FileUtils.readFileToString(expectedFile, StandardCharsets.UTF_8);
        assertEquals(expectedContent, actualContent);
    }

    @Test
    public void testNewCredsFile() throws Exception {
        CredentialsStore credStore = new CredentialsStore();
        final String userName = "Some User";
        credStore.addUser(userName, "SuperSecret");
        File tempFile = File.createTempFile("testNewCredsFile_actual","xml");
        credStore.save(tempFile);
        CredentialsStore testStore = CredentialsStore.fromFile(tempFile);
        UserCredentialsList credentialsList = testStore.getCredentialsList();
        assertEquals(1, credentialsList.getUser().size());
        boolean passwordMatches = testStore.checkPassword(userName, "SuperSecret");
        assertTrue(passwordMatches);
    }

    @Test
    public void testResetPassword() throws Exception {
        CredentialsStore credStore = CredentialsStore.fromFile(TEST_READ_WRITE_CREDENTIALS_FILE);
        final String userName = "Some User";
        credStore.addUser(userName, "SuperSecret");
        boolean passwordMatches = credStore.checkPassword(userName, "SuperSecret");
        assertTrue(passwordMatches);
        credStore.resetPassword(userName, "SuperDuperSecret");
        passwordMatches = credStore.checkPassword(userName, "SuperDuperSecret");
        assertTrue(passwordMatches);
    }

    @Test
    public void testCheckPassword() throws Exception {
        CredentialsStore credStore = CredentialsStore.fromFile(TEST_READ_WRITE_CREDENTIALS_FILE);
        final String userName = "Some User";
        credStore.addUser(userName, "SuperSecret");
        boolean passwordMatches = credStore.checkPassword(userName, "SuperSecret");
        assertTrue(passwordMatches);
        passwordMatches = credStore.checkPassword(userName, "WrongPassword");
        assertFalse(passwordMatches);
    }

    @Test
    public void testRemoveUser() throws Exception {
        CredentialsStore credStore = CredentialsStore.fromFile(TEST_READ_WRITE_CREDENTIALS_FILE);
        final String userName = "Some User";
        credStore.addUser(userName, "SuperSecret");
        boolean removed = credStore.removeUser(userName);
        assertTrue(removed);
        UserCredentials userCreds = credStore.findUser(userName);
        assertNull(userCreds);
        removed = credStore.removeUser(userName);
        assertFalse(removed);
    }

    @Test
    public void testCredentialsStoreReloadsFileUpdates() throws Exception {
        File tempFile = File.createTempFile("testCredentialsStoreReloadsFileUpdates_actual", "xml");
        CredentialsStore credStore = new CredentialsStore(tempFile);
        final String userName = "Some User";
        final String password1 = "SuperSecret1";
        credStore.addUser(userName, password1);
        credStore.save();
        boolean reloaded = credStore.reloadIfModified();
        assertFalse(reloaded);
        CredentialsStore testStore1 = CredentialsStore.fromFile(tempFile);
        CredentialsStore testStore2 = CredentialsStore.fromFile(tempFile);
        final String password2 = "SuperSecret2";
        testStore1.resetPassword(userName, password2);
        testStore1.save();
        // Ensure significant last modified diff on low-granularity file systems
        long lastModified = tempFile.lastModified();
        tempFile.setLastModified(lastModified + 5000);
        reloaded = testStore2.reloadIfModified();
        assertTrue(reloaded);
        boolean passwordMatches = testStore2.checkPassword(userName, password1);
        assertFalse(passwordMatches);
        passwordMatches = testStore2.checkPassword(userName, password2);
        assertTrue(passwordMatches);
    }

    @Test
    public void testSaveWithoutFileThrows() {
        CredentialsStore credStore = new CredentialsStore();
        final String userName = "Some User";
        final String password1 = "SuperSecret1";
        assertThrows(InvalidObjectException.class, () -> {
            credStore.addUser(userName, password1);
            credStore.save();
        });
    }

}
