package com.officevpn.storage;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.CopyOption;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.Set;

/**
 * Seam interface for departmental vault filesystem operations.
 * Allows deterministic fault injection, symlink simulation, and concurrent I/O testing.
 */
public interface VaultFileOps {
    SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException;
    Path move(Path source, Path target, CopyOption... options) throws IOException;
    Path copy(Path source, Path target, CopyOption... options) throws IOException;
    void delete(Path path) throws IOException;
    boolean deleteIfExists(Path path) throws IOException;
    long size(Path path) throws IOException;
    boolean isRegularFile(Path path, LinkOption... options);
    boolean exists(Path path, LinkOption... options);
}

