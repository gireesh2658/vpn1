package com.officevpn.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Central configuration manager. Loads configuration from classpath `/config.properties`
 * or filesystem, creating default configuration if absent.
 */
public final class ConfigUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigUtil.class);
    private static final String DEFAULT_RESOURCE = "/config.properties";
    private static final String FS_CONFIG_PATH = "src/main/resources/config.properties";

    private static final Properties PROPERTIES = new Properties();

    static {
        loadProperties();
    }

    private ConfigUtil() {}

    public static synchronized void loadProperties() {
        // 1. Try loading from classpath
        try (InputStream in = ConfigUtil.class.getResourceAsStream(DEFAULT_RESOURCE)) {
            if (in != null) {
                PROPERTIES.load(in);
                LOGGER.info("Loaded configuration from classpath resource: {}", DEFAULT_RESOURCE);
                return;
            }
        } catch (IOException e) {
            LOGGER.warn("Failed to load configuration from classpath: {}", e.getMessage());
        }

        // 2. Try loading from filesystem
        File file = new File(FS_CONFIG_PATH);
        if (file.exists()) {
            try (InputStream fin = new FileInputStream(file)) {
                PROPERTIES.load(fin);
                LOGGER.info("Loaded configuration from file: {}", file.getAbsolutePath());
                return;
            } catch (IOException e) {
                LOGGER.warn("Failed to load configuration from file {}: {}", file.getAbsolutePath(), e.getMessage());
            }
        }

        // 3. Populate and write defaults
        populateDefaults();
        saveDefaultFileIfPossible(file);
    }

    private static void populateDefaults() {
        PROPERTIES.setProperty("java.version", "25");
        PROPERTIES.setProperty("server.host", "0.0.0.0");
        PROPERTIES.setProperty("server.port", "8443");
        PROPERTIES.setProperty("server.maxClients", "50");
        PROPERTIES.setProperty("session.timeoutMinutes", "30");
        PROPERTIES.setProperty("session.absoluteTimeoutMinutes", "480");
        PROPERTIES.setProperty("db.host", "127.0.0.1");
        PROPERTIES.setProperty("db.port", "3306");
        PROPERTIES.setProperty("db.name", "office_vpn");
        PROPERTIES.setProperty("db.user", "root");
        PROPERTIES.setProperty("db.password", "");
        PROPERTIES.setProperty("db.pool.maxSize", "12");
        PROPERTIES.setProperty("db.url", "");
        PROPERTIES.setProperty("device.maxPerUser", "3");

        // Server & Client Paths / Defaults
        PROPERTIES.setProperty("server.dataDir", "server_data");
        PROPERTIES.setProperty("vault.rootDir", "server_vaults");
        PROPERTIES.setProperty("client.defaultHost", "127.0.0.1");
        PROPERTIES.setProperty("client.fingerprintStoreFile", "known_gateways.properties");

        // Tunneling & Virtual Subnet
        PROPERTIES.setProperty("vpn.gatewayVirtualIp", "10.8.0.1");
        PROPERTIES.setProperty("vpn.subnet.prefix", "10.8.0.");
        PROPERTIES.setProperty("vpn.branchSubnet.prefix", "10.9.0.");
        PROPERTIES.setProperty("tunnel.mode", "SPLIT");
        PROPERTIES.setProperty("tunnel.full.enabled", "true");
        PROPERTIES.setProperty("tunnel.split.officeDomains", "office.local,officevpn.local");
        PROPERTIES.setProperty("tunnel.split.officeSubnets", "10.8.0.0/24,10.9.0.0/24");
        PROPERTIES.setProperty("tunnel.split.bypassRoutes", "127.0.0.1,localhost,::1");

        // DNS Leak Protection
        PROPERTIES.setProperty("dns.vpn", "10.8.0.1");
        PROPERTIES.setProperty("dns.leakProtection", "true");

        // Transport
        PROPERTIES.setProperty("transport.preferred", "UDP");
        PROPERTIES.setProperty("transport.udp.port", "8443");
        PROPERTIES.setProperty("transport.tcp.port", "8443");
        PROPERTIES.setProperty("transport.udp.enabled", "true");

        // Site-to-Site
        PROPERTIES.setProperty("siteToSite.enabled", "true");
        PROPERTIES.setProperty("siteToSite.keepaliveSeconds", "15");

        // Bandwidth Control
        PROPERTIES.setProperty("bandwidth.defaultKbpsPerUser", "10240");
        PROPERTIES.setProperty("bandwidth.adminKbps", "51200");
        PROPERTIES.setProperty("bandwidth.employeeKbps", "10240");
        PROPERTIES.setProperty("bandwidth.enabled", "true");

        // Compression
        PROPERTIES.setProperty("compression.enabled", "true");
        PROPERTIES.setProperty("compression.thresholdBytes", "1024");
    }

    private static void saveDefaultFileIfPossible(File target) {
        try {
            File parent = target.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            try (OutputStream out = new FileOutputStream(target)) {
                PROPERTIES.store(out, "Auto-generated Office VPN Default Configuration");
                LOGGER.info("Saved default configuration to {}", target.getAbsolutePath());
            }
        } catch (IOException e) {
            LOGGER.debug("Could not write default config file: {}", e.getMessage());
        }
    }

    public static String getString(String key, String defaultValue) {
        return PROPERTIES.getProperty(key, defaultValue);
    }

    public static int getInt(String key, int defaultValue) {
        String val = PROPERTIES.getProperty(key);
        if (val == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid integer config for key '{}': {}", key, val);
            return defaultValue;
        }
    }

    public static boolean getBoolean(String key, boolean defaultValue) {
        String val = PROPERTIES.getProperty(key);
        if (val == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(val.trim());
    }

    public static String getHost() {
        return getString("server.host", "0.0.0.0");
    }

    public static int getPort() {
        return getInt("server.port", 8443);
    }

    public static String getClientDefaultHost() {
        return getConfigOverride("officevpn.client.host", "OFFICEVPN_CLIENT_HOST", "client.defaultHost", "127.0.0.1");
    }

    public static String getServerDataDir() {
        return getConfigOverride("officevpn.server.dataDir", "OFFICEVPN_SERVER_DATA_DIR", "server.dataDir", "server_data");
    }

    public static String getVaultRootDir() {
        return getConfigOverride("officevpn.vault.dir", "OFFICEVPN_VAULT_DIR", "vault.rootDir", "server_vaults");
    }

    public static String getFingerprintStoreFile() {
        return getString("client.fingerprintStoreFile", "known_gateways.properties");
    }

    public static String getGatewayVirtualIp() {
        return getString("vpn.gatewayVirtualIp", "10.8.0.1");
    }

    public static String getSubnetPrefix() {
        return getString("vpn.subnet.prefix", "10.8.0.");
    }

    public static String getBranchSubnetPrefix() {
        return getString("vpn.branchSubnet.prefix", "10.9.0.");
    }

    public static List<String> getOfficeSubnets() {
        String raw = getString("tunnel.split.officeSubnets", "10.8.0.0/24,10.9.0.0/24");
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    public static List<String> getTunnelBypassRoutes() {
        String raw = getString("tunnel.split.bypassRoutes", "127.0.0.1,localhost,::1");
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    public static String getDbHost() {
        return getConfigOverride("officevpn.db.host", "OFFICEVPN_DB_HOST", "db.host", "127.0.0.1");
    }

    public static int getDbPort() {
        String raw = getConfigOverride("officevpn.db.port", "OFFICEVPN_DB_PORT", "db.port", "3306");
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return 3306;
        }
    }

    public static String getDbName() {
        return getConfigOverride("officevpn.db.name", "OFFICEVPN_DB_NAME", "db.name", "office_vpn");
    }

    public static String getDbUser() {
        return getConfigOverride("officevpn.db.user", "OFFICEVPN_DB_USER", "db.user", "root");
    }

    public static String getDbPassword() {
        return getConfigOverride("officevpn.db.password", "OFFICEVPN_DB_PASS", "db.password", "");
    }

    public static int getDbPoolMaxSize() {
        int val = getInt("db.pool.maxSize", 12);
        return Math.max(2, Math.min(val, 64));
    }

    public static String getDbUrl() {
        String explicit = getConfigOverride("officevpn.db.url", "OFFICEVPN_DB_URL", "db.url", "");
        if (explicit != null && !explicit.isBlank()) {
            return explicit.trim();
        }
        return String.format(
                "jdbc:mysql://%s:%d/%s?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&useUnicode=true&characterEncoding=UTF-8",
                getDbHost(), getDbPort(), getDbName()
        );
    }

    private static String getConfigOverride(String sysProp, String envVar, String configKey, String fallback) {
        String prop = System.getProperty(sysProp);
        if (prop != null && !prop.isBlank()) {
            return prop.trim();
        }
        String env = System.getenv(envVar);
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return getString(configKey, fallback);
    }

    public static int getMaxClients() {
        return getInt("server.maxClients", 50);
    }

    public static int getSessionTimeoutMinutes() {
        return getInt("session.timeoutMinutes", 30);
    }

    public static int getAbsoluteTimeoutMinutes() {
        return getInt("session.absoluteTimeoutMinutes", 480);
    }

    public static String getTunnelMode() {
        return getString("tunnel.mode", "SPLIT");
    }

    public static int getMaxDevicesPerUser() {
        return getInt("device.maxPerUser", 3);
    }

    public static String getJavaVersion() {
        return getString("java.version", "25");
    }

    public static boolean isFullTunnelEnabled() {
        return getBoolean("tunnel.full.enabled", true);
    }

    public static List<String> getOfficeDomains() {
        String raw = getString("tunnel.split.officeDomains", "office.local,officevpn.local");
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    public static String getVpnDns() {
        return getString("dns.vpn", "10.8.0.1");
    }

    public static boolean isDnsLeakProtectionEnabled() {
        return getBoolean("dns.leakProtection", true);
    }

    public static String getPreferredTransport() {
        return getString("transport.preferred", "UDP");
    }

    public static int getUdpPort() {
        return getInt("transport.udp.port", 8443);
    }

    public static int getTcpPort() {
        return getInt("transport.tcp.port", 8443);
    }

    public static boolean isUdpEnabled() {
        return getBoolean("transport.udp.enabled", true);
    }

    public static boolean isSiteToSiteEnabled() {
        return getBoolean("siteToSite.enabled", true);
    }

    public static int getSiteToSiteKeepaliveSeconds() {
        return getInt("siteToSite.keepaliveSeconds", 15);
    }

    public static int getDefaultKbpsPerUser() {
        return getInt("bandwidth.defaultKbpsPerUser", 10240);
    }

    public static int getAdminKbps() {
        return getInt("bandwidth.adminKbps", 51200);
    }

    public static int getEmployeeKbps() {
        return getInt("bandwidth.employeeKbps", 10240);
    }

    public static boolean isBandwidthEnabled() {
        return getBoolean("bandwidth.enabled", true);
    }

    public static boolean isCompressionEnabled() {
        return getBoolean("compression.enabled", true);
    }

    public static int getCompressionThresholdBytes() {
        return getInt("compression.thresholdBytes", 1024);
    }

    public static void setPropertyForTest(String key, String value) {
        PROPERTIES.setProperty(key, value);
    }
}
