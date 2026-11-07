package com.officevpn.server;

/**
 * Immutable configuration defining server concurrency, rate limiting, connection quotas,
 * and pre-authentication bounds.
 */
public final class ServerLimits {

    private final int coreThreads;
    private final int maxThreads;
    private final int maxConnections;
    private final int perIpUnauthMax;
    private final int perIpHandshakesPerMinute;
    private final long handshakeDeadlineMillis;
    private final int preAuthReadTimeoutMillis;
    private final int trackedIpCap;
    private final int outboundQueueCapacity;
    private final long writeStallMillis;
    private final String bindAddress;

    public static final ServerLimits DEFAULT = builder().build();

    public static final ServerLimits RELAXED = builder()
            .coreThreads(16)
            .maxThreads(256)
            .maxConnections(5000)
            .perIpUnauthMax(10000)
            .perIpHandshakesPerMinute(10000)
            .handshakeDeadlineMillis(60000)
            .preAuthReadTimeoutMillis(60000)
            .trackedIpCap(50000)
            .outboundQueueCapacity(1024)
            .writeStallMillis(60000)
            .build();

    private ServerLimits(Builder builder) {
        this.coreThreads = builder.coreThreads;
        this.maxThreads = builder.maxThreads;
        this.maxConnections = builder.maxConnections;
        this.perIpUnauthMax = builder.perIpUnauthMax;
        this.perIpHandshakesPerMinute = builder.perIpHandshakesPerMinute;
        this.handshakeDeadlineMillis = builder.handshakeDeadlineMillis;
        this.preAuthReadTimeoutMillis = builder.preAuthReadTimeoutMillis;
        this.trackedIpCap = builder.trackedIpCap;
        this.outboundQueueCapacity = builder.outboundQueueCapacity;
        this.writeStallMillis = builder.writeStallMillis;
        this.bindAddress = builder.bindAddress;
    }

    public static Builder builder() {
        return new Builder();
    }

    public int getCoreThreads() {
        return coreThreads;
    }

    public int getMaxThreads() {
        return maxThreads;
    }

    public int getMaxConnections() {
        return maxConnections;
    }

    public int getPerIpUnauthMax() {
        return perIpUnauthMax;
    }

    public int getPerIpHandshakesPerMinute() {
        return perIpHandshakesPerMinute;
    }

    public long getHandshakeDeadlineMillis() {
        return handshakeDeadlineMillis;
    }

    public int getPreAuthReadTimeoutMillis() {
        return preAuthReadTimeoutMillis;
    }

    public int getTrackedIpCap() {
        return trackedIpCap;
    }

    public int getOutboundQueueCapacity() {
        return outboundQueueCapacity;
    }

    public long getWriteStallMillis() {
        return writeStallMillis;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    public String bindAddress() {
        return bindAddress;
    }

    public static final class Builder {
        private int coreThreads = 16;
        private int maxThreads = 256;
        private int maxConnections = 500;
        private int perIpUnauthMax = 10;
        private int perIpHandshakesPerMinute = 10;
        private long handshakeDeadlineMillis = 15000;
        private int preAuthReadTimeoutMillis = 15000;
        private int trackedIpCap = 50000;
        private int outboundQueueCapacity = 256;
        private long writeStallMillis = 10000;
        private String bindAddress = System.getProperty("officevpn.bind", "0.0.0.0");

        public Builder bindAddress(String bindAddress) {
            this.bindAddress = (bindAddress != null && !bindAddress.isBlank()) ? bindAddress.trim() : "0.0.0.0";
            return this;
        }

        public Builder coreThreads(int coreThreads) {
            this.coreThreads = coreThreads;
            return this;
        }

        public Builder maxThreads(int maxThreads) {
            this.maxThreads = maxThreads;
            return this;
        }

        public Builder maxConnections(int maxConnections) {
            this.maxConnections = maxConnections;
            return this;
        }

        public Builder perIpUnauthMax(int perIpUnauthMax) {
            this.perIpUnauthMax = perIpUnauthMax;
            return this;
        }

        public Builder perIpHandshakesPerMinute(int perIpHandshakesPerMinute) {
            this.perIpHandshakesPerMinute = perIpHandshakesPerMinute;
            return this;
        }

        public Builder handshakeDeadlineMillis(long handshakeDeadlineMillis) {
            this.handshakeDeadlineMillis = handshakeDeadlineMillis;
            return this;
        }

        public Builder preAuthReadTimeoutMillis(int preAuthReadTimeoutMillis) {
            this.preAuthReadTimeoutMillis = preAuthReadTimeoutMillis;
            return this;
        }

        public Builder trackedIpCap(int trackedIpCap) {
            this.trackedIpCap = trackedIpCap;
            return this;
        }

        public Builder outboundQueueCapacity(int outboundQueueCapacity) {
            this.outboundQueueCapacity = outboundQueueCapacity;
            return this;
        }

        public Builder writeStallMillis(long writeStallMillis) {
            this.writeStallMillis = writeStallMillis;
            return this;
        }

        public ServerLimits build() {
            return new ServerLimits(this);
        }
    }
}

