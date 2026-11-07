package com.officevpn.storage;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultSecurityTest {

    @Test
    @DisplayName("Path Traversal Defense: Rejects relative paths, parent directory traversals, and forbidden characters")
    void testPathTraversalDefense() {
        assertFalse(VaultManager.isValidFileName("../../etc/shadow"));
        assertFalse(VaultManager.isValidFileName("..\\boot.ini"));
        assertFalse(VaultManager.isValidFileName("nested/folder/file.txt"));
        assertFalse(VaultManager.isValidFileName("file:stream:$DATA"));
        assertFalse(VaultManager.isValidFileName("bad\0file.txt"));
        assertFalse(VaultManager.isValidFileName("trailingdot."));
        assertFalse(VaultManager.isValidFileName("trailingspace "));

        assertThrows(VaultException.class, () -> VaultManager.validateFileName("../../passwords.txt"));
        assertThrows(VaultException.class, () -> VaultManager.validateFileName("..\\secret.db"));
    }

    @Test
    @DisplayName("Windows Reserved Names: Rejects CON, PRN, AUX, NUL, COM1-9, LPT1-9 and variations")
    void testReservedDeviceNamesDefense() {
        assertFalse(VaultManager.isValidFileName("CON"));
        assertFalse(VaultManager.isValidFileName("con.txt"));
        assertFalse(VaultManager.isValidFileName("PRN.pdf"));
        assertFalse(VaultManager.isValidFileName("AUX"));
        assertFalse(VaultManager.isValidFileName("nul"));
        assertFalse(VaultManager.isValidFileName("com1.dat"));
        assertFalse(VaultManager.isValidFileName("lpt2.log"));

        assertThrows(VaultException.class, () -> VaultManager.validateFileName("con.txt"));
        assertThrows(VaultException.class, () -> VaultManager.validateFileName("NUL"));
    }

    @Test
    @DisplayName("Departmental Isolation: Blocks cross-department unauthorized vault access")
    void testDepartmentalIsolation(@TempDir Path tempVaultRoot, @TempDir Path tempDbDir) throws Exception {
        VaultManager vault = new VaultManager(tempVaultRoot);
        String dbPath = tempDbDir.resolve("vault_audit.db").toString();

        try (DatabaseManager db = new DatabaseManager(dbPath)) {
            UserAccount financeUser = new UserAccount(
                    1, "alice", "salt", "hash", Department.FINANCE, Role.EMPLOYEE, true, System.currentTimeMillis()
            );

            byte[] data = "Quarterly Financial Balance Sheet".getBytes(StandardCharsets.UTF_8);

            // Writing to user's own department succeeds
            vault.writeFile(financeUser, Department.FINANCE, "q3_balance.txt", data, db, "127.0.0.1");
            byte[] readBack = vault.readFile(financeUser, Department.FINANCE, "q3_balance.txt", db, "127.0.0.1");
            assertNotNull(readBack);
            assertEquals("Quarterly Financial Balance Sheet", new String(readBack, StandardCharsets.UTF_8));

            // Attempting cross-department access to HR vault must be denied
            SecurityException ex = assertThrows(SecurityException.class, () ->
                    vault.readFile(financeUser, Department.HR, "payroll.txt", db, "127.0.0.1")
            );
            assertTrue(ex.getMessage().contains("RBAC Access Denied"));
        }
    }

    @Test
    @DisplayName("Vault Version Pruning: Quotes fileName in regex and preserves unrelated version files")
    void testVaultVersionPruningRegex(@TempDir Path tempVaultRoot, @TempDir Path tempDbDir) throws Exception {
        VaultManager vault = new VaultManager(tempVaultRoot);
        String dbPath = tempDbDir.resolve("version_prune.db").toString();

        try (DatabaseManager db = new DatabaseManager(dbPath)) {
            UserAccount engUser = new UserAccount(
                    2, "bob", "salt", "hash", Department.IT, Role.EMPLOYEE, true, System.currentTimeMillis()
            );

            Path deptRoot = tempVaultRoot.resolve("IT");
            Path versionsDir = deptRoot.resolve(".versions");
            Files.createDirectories(versionsDir);

            // Create an unrelated file with similar prefix to ensure regex does not over-match
            Path unrelatedSimilar = versionsDir.resolve("spec.txt-backup.xml");
            Files.writeString(unrelatedSimilar, "Unrelated content that must not be deleted");

            // Write spec.txt 7 times to trigger pruning (MAX_BACKUP_VERSIONS = 5)
            for (int i = 1; i <= 7; i++) {
                byte[] content = ("Version iteration " + i).getBytes(StandardCharsets.UTF_8);
                vault.writeFile(engUser, Department.IT, "spec.txt", content, db, "127.0.0.1");
                Thread.sleep(20); // ensure distinct timestamps
            }

            // Verify unrelated file is still intact
            assertTrue(Files.exists(unrelatedSimilar), "Unrelated file must not be pruned by version cleaner");

            // Count remaining versions of spec.txt
            try (Stream<Path> stream = Files.list(versionsDir)) {
                List<Path> versions = stream
                        .filter(p -> p.getFileName().toString().matches("^spec\\.txt\\.\\d+$"))
                        .toList();
                assertEquals(5, versions.size(), "Only newest 5 backups of spec.txt should be retained");
            }
        }
    }
}
