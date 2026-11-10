package com.officevpn.ui.theme;

import javafx.scene.image.Image;
import javafx.scene.image.PixelFormat;
import javafx.scene.image.PixelReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.CRC32;
import java.util.zip.DeflaterOutputStream;

/**
 * Pure Java / JavaFX RGBA PNG encoder operating directly on JavaFX {@link PixelReader}
 * without relying on {@code java.awt.image.BufferedImage} or {@code javax.imageio}.
 */
public final class FxPngWriter {

    private static final byte[] PNG_SIGNATURE = {
            (byte) 137, 80, 78, 71, 13, 10, 26, 10
    };

    private FxPngWriter() {
    }

    /**
     * Encodes any JavaFX {@link Image} as a lossless 32-bit RGBA PNG byte array.
     */
    public static byte[] encode(Image image) throws IOException {
        int width = Math.max(1, (int) Math.round(image.getWidth()));
        int height = Math.max(1, (int) Math.round(image.getHeight()));
        PixelReader reader = image.getPixelReader();
        byte[] bgra = new byte[width * height * 4];
        reader.getPixels(0, 0, width, height, PixelFormat.getByteBgraInstance(), bgra, 0, width * 4);

        ByteArrayOutputStream rawScanlines = new ByteArrayOutputStream((width * 4 + 1) * height);
        for (int y = 0; y < height; y++) {
            rawScanlines.write(0); // filter type 0 (None)
            int rowStart = y * width * 4;
            for (int x = 0; x < width; x++) {
                int i = rowStart + x * 4;
                byte b = bgra[i];
                byte g = bgra[i + 1];
                byte r = bgra[i + 2];
                byte a = bgra[i + 3];
                rawScanlines.write(r);
                rawScanlines.write(g);
                rawScanlines.write(b);
                rawScanlines.write(a);
            }
        }

        ByteArrayOutputStream idatData = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflater = new DeflaterOutputStream(idatData)) {
            deflater.write(rawScanlines.toByteArray());
        }

        ByteArrayOutputStream png = new ByteArrayOutputStream(idatData.size() + 128);
        png.write(PNG_SIGNATURE);

        ByteBuffer ihdr = ByteBuffer.allocate(13);
        ihdr.putInt(width);
        ihdr.putInt(height);
        ihdr.put((byte) 8); // bit depth
        ihdr.put((byte) 6); // color type RGBA
        ihdr.put((byte) 0); // compression
        ihdr.put((byte) 0); // filter
        ihdr.put((byte) 0); // interlace
        writeChunk(png, new byte[]{'I', 'H', 'D', 'R'}, ihdr.array());
        writeChunk(png, new byte[]{'I', 'D', 'A', 'T'}, idatData.toByteArray());
        writeChunk(png, new byte[]{'I', 'E', 'N', 'D'}, new byte[0]);
        return png.toByteArray();
    }

    /**
     * Writes an encoded PNG directly to disk, creating parent directories if needed.
     */
    public static void write(Image image, Path target) throws IOException {
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        Files.write(target, encode(image));
    }

    private static void writeChunk(ByteArrayOutputStream out, byte[] type, byte[] data) throws IOException {
        ByteBuffer lenBuf = ByteBuffer.allocate(4);
        lenBuf.putInt(data.length);
        out.write(lenBuf.array());
        out.write(type);
        out.write(data);
        CRC32 crc = new CRC32();
        crc.update(type);
        crc.update(data);
        ByteBuffer crcBuf = ByteBuffer.allocate(4);
        crcBuf.putInt((int) crc.getValue());
        out.write(crcBuf.array());
    }
}

