package com.officevpn.client;

import com.officevpn.config.ConfigUtil;
import com.officevpn.model.Department;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Scanner;

/**
 * Interactive Console/CLI Client for the Office VPN System.
 * Delegates all networking, cryptographic handshakes, and vault operations to {@link VpnClientEngine}.
 */
public final class ConsoleClient implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsoleClient.class);

    private final VpnClientEngine engine;

    public ConsoleClient() {
        this(new VpnClientEngine());
    }

    public ConsoleClient(VpnClientEngine engine) {
        this.engine = engine;
    }

    public VpnClientEngine getEngine() {
        return engine;
    }

    /**
     * Establishes cryptographic handshake and performs authentication.
     */
    public boolean connectAndLogin(String host, int port, String username, String password, String fingerprint) {
        try {
            LOGGER.info("Initiating handshake with {}:{}...", host, port);
            engine.connectAndHandshake(host, port, fingerprint);
            LOGGER.info("Handshake complete. Authenticating user '{}'...", username);
            boolean ok = engine.login(username, password);
            if (ok) {
                LOGGER.info("Authentication succeeded. Assigned VIP: {}", engine.getAssignedVirtualIp());
            } else {
                LOGGER.warn("Authentication rejected by gateway.");
            }
            return ok;
        } catch (IOException e) {
            LOGGER.error("Connection or authentication error: {}", e.getMessage());
            return false;
        }
    }

    public boolean ping() {
        try {
            return engine.ping();
        } catch (IOException e) {
            LOGGER.error("Ping failed: {}", e.getMessage());
            return false;
        }
    }

    public List<String> listVaultFiles(Department dept) {
        try {
            return engine.listDepartmentFiles(dept);
        } catch (IOException e) {
            LOGGER.error("Failed to list vault files for {}: {}", dept, e.getMessage());
            return List.of();
        }
    }

    public boolean uploadFile(Department dept, String fileName, byte[] data) {
        try {
            engine.uploadFile(dept, fileName, data);
            return true;
        } catch (IOException e) {
            LOGGER.error("Upload failed: {}", e.getMessage());
            return false;
        }
    }

    public byte[] downloadFile(Department dept, String fileName) {
        try {
            return engine.downloadFile(dept, fileName);
        } catch (IOException e) {
            LOGGER.error("Download failed: {}", e.getMessage());
            return null;
        }
    }

    public void disconnect() {
        engine.disconnect();
    }

    @Override
    public void close() {
        disconnect();
    }

    public boolean isConnected() {
        return engine.isConnected() && engine.isAuthenticated();
    }

    public static void printBanner() {
        System.out.println("========================================================================");
        System.out.println("          OFFICE VPN CONSOLE CLIENT - SECURE EMPLOYEE TERMINAL          ");
        System.out.println("          AES-256-GCM + HKDF-SHA256 + RSA-2048 Cryptographic Handshake ");
        System.out.println("========================================================================");
    }

    public static void main(String[] args) {
        printBanner();
        try (Scanner scanner = new Scanner(System.in);
             ConsoleClient client = new ConsoleClient()) {

            String defaultHost = ConfigUtil.getHost();
            int defaultPort = ConfigUtil.getPort();

            System.out.print("Server Host [" + defaultHost + "]: ");
            String hostInput = scanner.nextLine().trim();
            String host = hostInput.isEmpty() ? defaultHost : hostInput;

            System.out.print("Server Port [" + defaultPort + "]: ");
            String portInput = scanner.nextLine().trim();
            int port = portInput.isEmpty() ? defaultPort : Integer.parseInt(portInput);

            System.out.print("Username (e.g. alice_fin, gireesh, admin): ");
            String username = scanner.nextLine().trim();

            System.out.print("Password: ");
            String password = scanner.nextLine().trim();

            System.out.print("Pinned Fingerprint (press Enter to accept unpinned): ");
            String fp = scanner.nextLine().trim();
            if (fp.isEmpty()) {
                fp = null;
            }

            boolean loggedIn = client.connectAndLogin(host, port, username, password, fp);
            if (!loggedIn) {
                System.out.println("\n[ERROR] Login failed. Exiting.");
                return;
            }

            System.out.println("\n[SUCCESS] Connected to Office VPN! Assigned Virtual IP: "
                    + client.getEngine().getAssignedVirtualIp());

            boolean running = true;
            while (running && client.isConnected()) {
                System.out.println("\n--- Office VPN Menu ---");
                System.out.println("1. Ping Gateway");
                System.out.println("2. List Vault Files");
                System.out.println("3. Download File");
                System.out.println("4. Upload File");
                System.out.println("5. Send Chat Message");
                System.out.println("6. Disconnect & Exit");
                System.out.print("Select option (1-6): ");

                String opt = scanner.nextLine().trim();
                switch (opt) {
                    case "1" -> {
                        boolean pong = client.ping();
                        System.out.println(pong ? "[OK] Pong received from gateway!" : "[FAIL] No response from gateway.");
                    }
                    case "2" -> {
                        Department userDept = client.getEngine().getDepartment();
                        System.out.println("Files in " + userDept + " vault:");
                        List<String> files = client.listVaultFiles(userDept);
                        if (files.isEmpty()) {
                            System.out.println("  (No files found)");
                        } else {
                            files.forEach(f -> System.out.println("  - " + f));
                        }
                    }
                    case "3" -> {
                        Department userDept = client.getEngine().getDepartment();
                        System.out.print("Enter file name to download: ");
                        String dlFile = scanner.nextLine().trim();
                        byte[] content = client.downloadFile(userDept, dlFile);
                        if (content != null) {
                            System.out.println("[OK] Downloaded " + content.length + " bytes.");
                        } else {
                            System.out.println("[FAIL] Could not download file: " + dlFile);
                        }
                    }
                    case "4" -> {
                        Department userDept = client.getEngine().getDepartment();
                        System.out.print("Enter local file path to upload: ");
                        String path = scanner.nextLine().trim();
                        File f = new File(path);
                        if (!f.exists() || !f.isFile()) {
                            System.out.println("[ERROR] Local file not found: " + path);
                        } else {
                            byte[] data = Files.readAllBytes(f.toPath());
                            boolean ok = client.uploadFile(userDept, f.getName(), data);
                            System.out.println(ok ? "[OK] Upload succeeded!" : "[FAIL] Upload failed.");
                        }
                    }
                    case "5" -> {
                        System.out.print("Enter message: ");
                        String msg = scanner.nextLine().trim();
                        client.getEngine().sendChatMessage(msg);
                        System.out.println("[OK] Message sent.");
                    }
                    case "6" -> {
                        client.disconnect();
                        running = false;
                        System.out.println("Disconnected.");
                    }
                    default -> System.out.println("Invalid option.");
                }
            }
        } catch (Exception e) {
            LOGGER.error("Console client error: {}", e.getMessage(), e);
        }
    }
}

