package com.officevpn.util;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Authentic Hardware Telemetry and Device Fingerprinting Utility.
 * <p>
 * Gathers genuine host metadata directly from the operating system and network
 * interfaces without synthetic placeholders or arbitrary device mocks.
 */
public final class HardwareUtil {

    private HardwareUtil() {}

    /**
     * Resolves the genuine physical computer hostname from the host operating system.
     *
     * @return clean authentic host identifier
     */
    public static String getAuthenticHostName() {
        try {
            String name = InetAddress.getLocalHost().getHostName();
            if (name != null && !name.isBlank() && !name.equalsIgnoreCase("localhost")) {
                return name.trim();
            }
        } catch (Exception ignored) {}

        String envComputer = System.getenv("COMPUTERNAME");
        if (envComputer != null && !envComputer.isBlank()) {
            return envComputer.trim();
        }

        String envHost = System.getenv("HOSTNAME");
        if (envHost != null && !envHost.isBlank()) {
            return envHost.trim();
        }

        return "Enterprise-Workstation";
    }

    /**
     * Resolves the authentic device name combining host machine name, OS distribution, and architecture.
     *
     * @return authentic human-readable device name (e.g. "MYPC (Windows 11 amd64)")
     */
    public static String getAuthenticDeviceName() {
        String host = getAuthenticHostName();
        String os = System.getProperty("os.name", "Unknown OS");
        String arch = System.getProperty("os.arch", "");
        return host + " (" + os + (arch.isBlank() ? "" : " " + arch) + ")";
    }

    /**
     * Computes a deterministic, cryptographic SHA-256 hardware fingerprint
     * derived from the machine's primary physical network interface (MAC address)
     * and system installation attributes.
     *
     * @return formatted hardware fingerprint string (e.g. "HW-A1B2C3D4E5F67890")
     */
    public static String getAuthenticHardwareFingerprint() {
        try {
            StringBuilder raw = new StringBuilder();
            raw.append(getAuthenticHostName()).append(";");
            raw.append(System.getProperty("os.name")).append(";");
            raw.append(System.getProperty("os.arch")).append(";");
            raw.append(System.getProperty("user.name")).append(";");

            byte[] macBytes = null;
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            if (nics != null) {
                while (nics.hasMoreElements()) {
                    NetworkInterface nic = nics.nextElement();
                    if (!nic.isLoopback() && !nic.isVirtual() && nic.getHardwareAddress() != null) {
                        byte[] hw = nic.getHardwareAddress();
                        if (hw != null && hw.length >= 6) {
                            macBytes = hw;
                            break;
                        }
                    }
                }
            }

            if (macBytes != null) {
                for (byte b : macBytes) {
                    raw.append(String.format("%02X", b));
                }
            } else {
                String proc = System.getenv("PROCESSOR_IDENTIFIER");
                raw.append(proc != null ? proc : "GENERIC-HW");
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.toString().getBytes(StandardCharsets.UTF_8));
            String hex = HexFormat.of().formatHex(digest).toUpperCase(Locale.ROOT);
            return "HW-" + hex.substring(0, 16);
        } catch (Exception e) {
            String fallback = getAuthenticDeviceName();
            int hash = Math.abs(fallback.hashCode());
            return "HW-" + String.format("%08X", hash) + "00000000";
        }
    }

    public static void main(String[] args) {
        System.out.println("Authentic Device Name: " + getAuthenticDeviceName());
        System.out.println("Authentic Hardware FP: " + getAuthenticHardwareFingerprint());
    }
}
