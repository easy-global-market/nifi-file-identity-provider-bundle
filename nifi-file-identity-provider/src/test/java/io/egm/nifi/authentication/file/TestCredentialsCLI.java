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

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.nio.file.Paths;

import io.egm.nifi.authentication.file.CredentialsCLI.CredentialsAction;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;


public class TestCredentialsCLI {

    private static final String TEST_CLI_CREDENTIALS_FILE = "src/test/resources/test_cli_credentials.xml";
    private String credentialsFilePath;
    private String tempFolderPath;

    @TempDir
    public Path folder;

    @BeforeEach
    public void setupTestCredentialsFile() throws Exception {
        //final File tempFolder = folder.newFolder();
        tempFolderPath = folder.toAbsolutePath().toString();
        credentialsFilePath = Paths.get(tempFolderPath, "credentials.xml").toString();
        final File resourceFile = new File(TEST_CLI_CREDENTIALS_FILE);
        final File tempFile = new File(credentialsFilePath);
        FileUtils.copyFile(resourceFile, tempFile);
    }

    @Test
    public void testHelp() throws Exception {
        final String[] args = new String[]{};
        final CredentialsCLI cli = new CredentialsCLI();
        final CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.PrintHelpAction.class, action.getClass());
        action.execute();
        final String helpText = StringUtils.join(action.outputs, "\n");
        assertTrue(helpText.contains("Usage"));
    }

    @Test
    public void testUnknownCommandsGetHelp() {
        String[] args = new String[]{"bogus"};
        final CredentialsCLI cli = new CredentialsCLI();
        CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.PrintHelpAction.class, action.getClass());
        args = new String[]{"bogus", "user", "password"};
        action = cli.processArgs(args);
        assertEquals(CredentialsCLI.PrintHelpAction.class, action.getClass());
    }

    @Test
    public void testListWithoutFilePrintsError() {
        final String[] args = new String[]{"list"};
        final CredentialsCLI cli = new CredentialsCLI();
        final CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.PrintHelpAction.class, action.getClass());
    }

    @Test
    public void testListWithBadFileThrows() {
        final String[] args = new String[]{"list", "NoSuchFile.xml"};
        final CredentialsCLI cli = new CredentialsCLI();
        final CredentialsAction action = cli.processArgs(args);
        assertThrows(FileNotFoundException.class, action::validate);
    }

    @Test
    public void testListUsersSimple() throws Exception {
        final String[] args = new String[]{"list", credentialsFilePath};
        final CredentialsCLI cli = new CredentialsCLI();
        final CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.ListUsersAction.class, action.getClass());
        action.execute();
        assertEquals(action.outputs.length, 6);
        assertEquals(action.outputs[0], "user1");
    }

    @Test
    public void testAddUserCreatesFile() throws Exception {
        final String credentialsFilePath = Paths.get(tempFolderPath, "testAddUserCreatesFile.xml").toString();
        final String[] args = new String[]{"add", credentialsFilePath, "someuser"};
        final CredentialsCLI cli = new CredentialsCLI();
        final CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.AddUserAction.class, action.getClass());
        action.secureInput = "password1".toCharArray();
        action.execute();
        assertEquals(action.outputs.length, 1);
        assertTrue(action.outputs[0].contains("someuser"));
        final CredentialsStore credStore = CredentialsStore.fromFile(credentialsFilePath);
        boolean passwordMatches = credStore.checkPassword("someuser", "password1");
        assertTrue(passwordMatches);

    }

    @Test
    public void testResetPassword() throws Exception {
        final String userName = "user1";
        final String[] args = new String[]{"reset", credentialsFilePath, "user1"};
        final CredentialsCLI cli = new CredentialsCLI();
        final CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.ResetPasswordAction.class, action.getClass());
        action.secureInput = "ResetPassword".toCharArray();
        action.execute();
        assertEquals(action.outputs.length, 1);
        assertTrue(action.outputs[0].contains("user1"));
        final CredentialsStore credStore = CredentialsStore.fromFile(credentialsFilePath);
        boolean passwordMatches = credStore.checkPassword(userName, "ResetPassword");
        assertTrue(passwordMatches);
    }

    @Test
    public void testRemoveUser() throws Exception {
        final String userName = "user1";
        final String[] args = new String[]{"remove", credentialsFilePath, userName};
        final CredentialsCLI cli = new CredentialsCLI();
        CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.RemoveUserAction.class, action.getClass());
        action.execute();
        assertEquals(action.outputs.length, 1);
        assertTrue(action.outputs[0].contains(userName));
        action = cli.processArgs(new String[] {"list", credentialsFilePath});
        action.execute();
        assertEquals(5, action.outputs.length);
    }

    @Test
    public void testRemoveUserNoParameter() {
        final String[] args = new String[]{"remove", credentialsFilePath};
        final CredentialsCLI cli = new CredentialsCLI();
        CredentialsAction action = cli.processArgs(args);
        assertEquals(CredentialsCLI.RemoveUserAction.class, action.getClass());
        assertThrows(IllegalArgumentException.class, action::validate);
    }

}
