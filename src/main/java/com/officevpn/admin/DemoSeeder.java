package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Ephemeral demonstration credentials seeder.
 * Only invoked when JVM parameter {@code -Dofficevpn.demo=true} is explicitly provided.
 * Generates high-entropy random passwords per runtime invocation.
 */
public final class DemoSeeder {

    public static final String DEMO_FLAG_PROPERTY = "officevpn.demo";

    public record DemoAccount(String username, String password, Department department, Role role) {}

    private DemoSeeder() {}

    /**
     * Checks if the JVM was started with the demo flag.
     */
    public static boolean isDemoEnabled() {
        return Boolean.getBoolean(DEMO_FLAG_PROPERTY);
    }

    /**
     * Seeds initial demonstration accounts if the database is completely empty.
     *
     * @param db database manager
     * @return unmodifiable list of created demo accounts and their temporary credentials
     */
    public static List<DemoAccount> seed(DatabaseManager db) {
        Objects.requireNonNull(db, "DatabaseManager cannot be null");

        if (!db.listAllUsers().isEmpty()) {
            return Collections.emptyList();
        }

        List<DemoAccount> created = new ArrayList<>();
        created.add(createAccount(db, "admin_hq", PasswordPolicy.generateStrongPassword(16), Department.HEADQUARTERS, Role.ADMIN));
        created.add(createAccount(db, "alice_fin", PasswordPolicy.generateStrongPassword(16), Department.FINANCE, Role.EMPLOYEE));
        created.add(createAccount(db, "bob_hr", PasswordPolicy.generateStrongPassword(16), Department.HR, Role.EMPLOYEE));
        created.add(createAccount(db, "charlie_it", PasswordPolicy.generateStrongPassword(16), Department.IT, Role.EMPLOYEE));
        created.add(createAccount(db, "david_auditor", PasswordPolicy.generateStrongPassword(16), Department.FINANCE, Role.AUDITOR));

        return Collections.unmodifiableList(created);
    }

    private static DemoAccount createAccount(DatabaseManager db, String username, String password, Department dept, Role role) {
        char[] pwChars = password.toCharArray();
        try {
            db.createUser(username, pwChars, dept, role, "DEMO_SEEDER");
            return new DemoAccount(username, password, dept, role);
        } finally {
            java.util.Arrays.fill(pwChars, '\0');
        }
    }
}

