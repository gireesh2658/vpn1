package com.officevpn.security;

import javafx.scene.image.PixelWriter;
import javafx.scene.image.WritableImage;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure-Java ISO/IEC 18004 QR Code encoder (Byte mode, Error Correction Level M, Versions 1..10)
 * for scannable TOTP authenticator provisioning URIs without external dependencies.
 */
public final class QrCodeUtil {

    // ECC Level M block specs for versions 1..10:
    // {totalDataCodewords, ecPerBlock, g1Blocks, g1DataPerBlock, g2Blocks, g2DataPerBlock}
    private static final int[][] ECC_M_SPEC = {
            null,
            {16, 10, 1, 16, 0, 0},   // V1  (26 total)
            {28, 16, 1, 28, 0, 0},   // V2  (44 total)
            {44, 26, 1, 44, 0, 0},   // V3  (70 total)
            {64, 18, 2, 32, 0, 0},   // V4  (100 total)
            {86, 24, 2, 43, 0, 0},   // V5  (134 total)
            {108, 16, 4, 27, 0, 0},  // V6  (172 total)
            {124, 18, 4, 31, 0, 0},  // V7  (196 total)
            {154, 22, 2, 38, 2, 39}, // V8  (242 total)
            {182, 22, 3, 36, 2, 37}, // V9  (292 total)
            {216, 26, 4, 43, 1, 44}  // V10 (346 total)
    };

    private static final int[][] ALIGNMENT_POS = {
            {}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
            {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}
    };

    private QrCodeUtil() {}

    /**
     * Encodes UTF-8 payload into a boolean QR matrix (true = dark module, false = light module).
     */
    public static boolean[][] encode(String text) {
        Objects.requireNonNull(text, "QR payload cannot be null");
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);

        int version = selectVersion(payload.length);
        int[] spec = ECC_M_SPEC[version];
        int totalDataCodewords = spec[0];
        int ecPerBlock = spec[1];

        byte[] dataCodewords = encodeDataBytes(payload, version, totalDataCodewords);
        byte[] allCodewords = interleaveWithEcc(dataCodewords, spec, ecPerBlock);

        int size = 17 + 4 * version;
        boolean[][] isFunction = new boolean[size][size];
        boolean[][] modules = new boolean[size][size];

        drawFunctionPatterns(version, size, modules, isFunction);
        drawCodewords(allCodewords, size, modules, isFunction);

        int bestMask = 0;
        int minPenalty = Integer.MAX_VALUE;
        for (int mask = 0; mask < 8; mask++) {
            boolean[][] candidate = copyMatrix(modules);
            applyMask(candidate, isFunction, mask);
            drawFormatBits(candidate, mask);
            int penalty = calculatePenalty(candidate);
            if (penalty < minPenalty) {
                minPenalty = penalty;
                bestMask = mask;
            }
        }

        applyMask(modules, isFunction, bestMask);
        drawFormatBits(modules, bestMask);
        return modules;
    }

    /**
     * Renders a QR matrix directly to a JavaFX WritableImage with crisp pixel-aligned modules.
     */
    public static WritableImage toFxImage(boolean[][] matrix, int modulePx, int quietModules, int fgArgb, int bgArgb) {
        int n = matrix.length;
        int dim = (n + quietModules * 2) * modulePx;
        WritableImage img = new WritableImage(dim, dim);
        PixelWriter pw = img.getPixelWriter();
        for (int y = 0; y < dim; y++) {
            int mr = (y / modulePx) - quietModules;
            for (int x = 0; x < dim; x++) {
                int mc = (x / modulePx) - quietModules;
                boolean dark = mr >= 0 && mr < n && mc >= 0 && mc < n && matrix[mr][mc];
                pw.setArgb(x, y, dark ? fgArgb : bgArgb);
            }
        }
        return img;
    }

    private static int selectVersion(int byteLen) {
        for (int v = 1; v <= 10; v++) {
            int ccBits = (v <= 9) ? 8 : 16;
            int totalBits = ECC_M_SPEC[v][0] * 8;
            if (4 + ccBits + byteLen * 8 <= totalBits) {
                return v;
            }
        }
        throw new IllegalArgumentException("QR payload exceeds maximum capacity (213 UTF-8 bytes): " + byteLen);
    }

    private static byte[] encodeDataBytes(byte[] payload, int version, int totalDataCodewords) {
        BitBuffer bb = new BitBuffer(totalDataCodewords * 8);
        bb.appendBits(0b0100, 4); // Byte mode indicator
        int ccBits = (version <= 9) ? 8 : 16;
        bb.appendBits(payload.length, ccBits);
        for (byte b : payload) {
            bb.appendBits(b & 0xFF, 8);
        }
        int capacityBits = totalDataCodewords * 8;
        int terminatorLen = Math.min(4, capacityBits - bb.length);
        bb.appendBits(0, terminatorLen);
        while (bb.length % 8 != 0) {
            bb.appendBits(0, 1);
        }
        byte[] result = new byte[totalDataCodewords];
        int filledBytes = bb.length / 8;
        for (int i = 0; i < filledBytes; i++) {
            result[i] = bb.getByte(i);
        }
        boolean toggle = true;
        for (int i = filledBytes; i < totalDataCodewords; i++) {
            result[i] = (byte) (toggle ? 0xEC : 0x11);
            toggle = !toggle;
        }
        return result;
    }

    private static byte[] interleaveWithEcc(byte[] data, int[] spec, int ecLen) {
        int g1Blocks = spec[2];
        int g1Len = spec[3];
        int g2Blocks = spec[4];
        int g2Len = spec[5];
        int totalBlocks = g1Blocks + g2Blocks;
        int maxDataLen = Math.max(g1Len, g2Len);

        byte[][] dataBlocks = new byte[totalBlocks][];
        byte[][] eccBlocks = new byte[totalBlocks][];
        int[] rsDiv = reedSolomonComputeDivisor(ecLen);

        int pos = 0;
        for (int b = 0; b < totalBlocks; b++) {
            int len = (b < g1Blocks) ? g1Len : g2Len;
            byte[] block = new byte[len];
            System.arraycopy(data, pos, block, 0, len);
            pos += len;
            dataBlocks[b] = block;
            eccBlocks[b] = reedSolomonComputeRemainder(block, rsDiv);
        }

        List<Byte> out = new ArrayList<>(data.length + totalBlocks * ecLen);
        for (int i = 0; i < maxDataLen; i++) {
            for (int b = 0; b < totalBlocks; b++) {
                if (i < dataBlocks[b].length) {
                    out.add(dataBlocks[b][i]);
                }
            }
        }
        for (int i = 0; i < ecLen; i++) {
            for (int b = 0; b < totalBlocks; b++) {
                out.add(eccBlocks[b][i]);
            }
        }

        byte[] res = new byte[out.size()];
        for (int i = 0; i < out.size(); i++) {
            res[i] = out.get(i);
        }
        return res;
    }

    private static int[] reedSolomonComputeDivisor(int degree) {
        int[] result = new int[degree];
        result[degree - 1] = 1;
        int root = 1;
        for (int i = 0; i < degree; i++) {
            for (int j = 0; j < degree; j++) {
                result[j] = gfMul(result[j], root);
                if (j + 1 < degree) {
                    result[j] ^= result[j + 1];
                }
            }
            root = gfMul(root, 0x02);
        }
        return result;
    }

    private static byte[] reedSolomonComputeRemainder(byte[] data, int[] divisor) {
        int degree = divisor.length;
        int[] rem = new int[degree];
        for (byte b : data) {
            int factor = (b & 0xFF) ^ rem[0];
            System.arraycopy(rem, 1, rem, 0, degree - 1);
            rem[degree - 1] = 0;
            for (int i = 0; i < degree; i++) {
                rem[i] ^= gfMul(divisor[i], factor);
            }
        }
        byte[] out = new byte[degree];
        for (int i = 0; i < degree; i++) {
            out[i] = (byte) rem[i];
        }
        return out;
    }

    private static int gfMul(int x, int y) {
        int z = 0;
        for (int i = 7; i >= 0; i--) {
            z = (z << 1) ^ ((z >>> 7) * 0x11D);
            z ^= ((y >>> i) & 1) * x;
        }
        return z;
    }

    private static void drawFunctionPatterns(int version, int size, boolean[][] modules, boolean[][] isFn) {
        // Timing patterns
        for (int i = 0; i < size; i++) {
            setFn(modules, isFn, 6, i, i % 2 == 0);
            setFn(modules, isFn, i, 6, i % 2 == 0);
        }

        // Finder patterns + separators
        drawFinderPattern(modules, isFn, 3, 3, size);
        drawFinderPattern(modules, isFn, size - 4, 3, size);
        drawFinderPattern(modules, isFn, 3, size - 4, size);

        // Dark module
        setFn(modules, isFn, 8, size - 8, true);

        // Alignment patterns
        int[] centers = ALIGNMENT_POS[version];
        for (int r : centers) {
            for (int c : centers) {
                if ((r == 6 && c == 6) || (r == 6 && c == size - 7) || (r == size - 7 && c == 6)) {
                    continue;
                }
                drawAlignmentPattern(modules, isFn, c, r);
            }
        }

        // Format info reservation
        for (int i = 0; i <= 8; i++) {
            if (i != 6) {
                isFn[8][i] = true;
                isFn[i][8] = true;
            }
        }
        for (int i = size - 8; i < size; i++) {
            isFn[8][i] = true;
            isFn[i][8] = true;
        }

        // Version info (versions >= 7)
        if (version >= 7) {
            int rem = version;
            for (int i = 0; i < 12; i++) {
                rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
            }
            int bits = (version << 12) | rem;
            for (int i = 0; i < 18; i++) {
                boolean bit = ((bits >>> i) & 1) != 0;
                int a = size - 11 + (i % 3);
                int b = i / 3;
                setFn(modules, isFn, a, b, bit);
                setFn(modules, isFn, b, a, bit);
            }
        }
    }

    private static void drawFinderPattern(boolean[][] modules, boolean[][] isFn, int cx, int cy, int size) {
        for (int dy = -4; dy <= 4; dy++) {
            for (int dx = -4; dx <= 4; dx++) {
                int x = cx + dx;
                int y = cy + dy;
                if (x < 0 || x >= size || y < 0 || y >= size) continue;
                int dist = Math.max(Math.abs(dx), Math.abs(dy));
                boolean dark = dist != 2 && dist != 4;
                setFn(modules, isFn, x, y, dark);
            }
        }
    }

    private static void drawAlignmentPattern(boolean[][] modules, boolean[][] isFn, int cx, int cy) {
        for (int dy = -2; dy <= 2; dy++) {
            for (int dx = -2; dx <= 2; dx++) {
                int dist = Math.max(Math.abs(dx), Math.abs(dy));
                setFn(modules, isFn, cx + dx, cy + dy, dist != 1);
            }
        }
    }

    private static void setFn(boolean[][] modules, boolean[][] isFn, int x, int y, boolean dark) {
        modules[y][x] = dark;
        isFn[y][x] = true;
    }

    private static void drawCodewords(byte[] codewords, int size, boolean[][] modules, boolean[][] isFn) {
        int bitIdx = 0;
        int totalBits = codewords.length * 8;
        for (int right = size - 1; right >= 1; right -= 2) {
            if (right == 6) right = 5;
            for (int vert = 0; vert < size; vert++) {
                for (int j = 0; j < 2; j++) {
                    int x = right - j;
                    boolean upward = ((right + 1) & 2) == 0;
                    int y = upward ? (size - 1 - vert) : vert;
                    if (!isFn[y][x] && bitIdx < totalBits) {
                        boolean dark = ((codewords[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1) != 0;
                        modules[y][x] = dark;
                        bitIdx++;
                    }
                }
            }
        }
    }

    private static void applyMask(boolean[][] modules, boolean[][] isFn, int mask) {
        int n = modules.length;
        for (int r = 0; r < n; r++) {
            for (int c = 0; c < n; c++) {
                if (isFn[r][c]) continue;
                boolean invert = switch (mask) {
                    case 0 -> (r + c) % 2 == 0;
                    case 1 -> r % 2 == 0;
                    case 2 -> c % 3 == 0;
                    case 3 -> (r + c) % 3 == 0;
                    case 4 -> (r / 2 + c / 3) % 2 == 0;
                    case 5 -> ((r * c) % 2) + ((r * c) % 3) == 0;
                    case 6 -> (((r * c) % 2) + ((r * c) % 3)) % 2 == 0;
                    case 7 -> (((r + c) % 2) + ((r * c) % 3)) % 2 == 0;
                    default -> false;
                };
                if (invert) {
                    modules[r][c] = !modules[r][c];
                }
            }
        }
    }

    private static void drawFormatBits(boolean[][] modules, int mask) {
        // ECC Level M = format indicator 00 (0), concatenated with 3-bit mask -> 5 bits
        int data = mask & 0b111; // since Level M = 00
        int rem = data;
        for (int i = 0; i < 10; i++) {
            rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
        }
        int bits = ((data << 10) | rem) ^ 0x5412;

        int size = modules.length;
        // Copy 1: top-left (bit 0 at top -> bit 14 at left)
        for (int i = 0; i <= 5; i++) {
            modules[i][8] = ((bits >>> i) & 1) != 0;
        }
        modules[7][8] = ((bits >>> 6) & 1) != 0;
        modules[8][8] = ((bits >>> 7) & 1) != 0;
        modules[8][7] = ((bits >>> 8) & 1) != 0;
        for (int i = 9; i < 15; i++) {
            modules[8][14 - i] = ((bits >>> i) & 1) != 0;
        }
        // Copy 2: bits 0..7 top-right (right -> left), bits 8..14 bottom-left (top -> bottom)
        for (int i = 0; i < 8; i++) {
            modules[8][size - 1 - i] = ((bits >>> i) & 1) != 0;
        }
        for (int i = 8; i < 15; i++) {
            modules[size - 15 + i][8] = ((bits >>> i) & 1) != 0;
        }
    }

    private static int calculatePenalty(boolean[][] m) {
        int n = m.length;
        int penalty = 0;
        // Rule 1: horizontal and vertical runs >= 5
        for (int r = 0; r < n; r++) {
            int runH = 0;
            int runV = 0;
            boolean prevH = false;
            boolean prevV = false;
            for (int c = 0; c < n; c++) {
                boolean h = m[r][c];
                if (c > 0 && h == prevH) {
                    runH++;
                    if (runH == 5) penalty += 3;
                    else if (runH > 5) penalty += 1;
                } else {
                    prevH = h;
                    runH = 1;
                }
                boolean v = m[c][r];
                if (c > 0 && v == prevV) {
                    runV++;
                    if (runV == 5) penalty += 3;
                    else if (runV > 5) penalty += 1;
                } else {
                    prevV = v;
                    runV = 1;
                }
            }
        }
        // Rule 2: 2x2 blocks
        for (int r = 0; r < n - 1; r++) {
            for (int c = 0; c < n - 1; c++) {
                boolean color = m[r][c];
                if (color == m[r][c + 1] && color == m[r + 1][c] && color == m[r + 1][c + 1]) {
                    penalty += 3;
                }
            }
        }
        // Rule 3: finder-like 1:1:3:1:1 patterns
        for (int r = 0; r < n; r++) {
            for (int c = 0; c <= n - 7; c++) {
                if (matchesFinderLike(m, r, c, true)) penalty += 40;
                if (matchesFinderLike(m, c, r, false)) penalty += 40;
            }
        }
        // Rule 4: dark ratio deviation from 50%
        int darkCount = 0;
        for (boolean[] row : m) {
            for (boolean cell : row) {
                if (cell) darkCount++;
            }
        }
        int total = n * n;
        int k = Math.abs(darkCount * 20 - total * 10) / total;
        penalty += k * 10;
        return penalty;
    }

    private static boolean matchesFinderLike(boolean[][] m, int a, int b, boolean horizontal) {
        int n = m.length;
        boolean base = horizontal
                ? (m[a][b] && !m[a][b + 1] && m[a][b + 2] && m[a][b + 3] && m[a][b + 4] && !m[a][b + 5] && m[a][b + 6])
                : (m[a][b] && !m[a + 1][b] && m[a + 2][b] && m[a + 3][b] && m[a + 4][b] && !m[a + 5][b] && m[a + 6][b]);
        if (!base) return false;
        boolean clearBefore = true;
        for (int k = 1; k <= 4; k++) {
            int idx = (horizontal ? b : a) - k;
            boolean dark = idx >= 0 && (horizontal ? m[a][idx] : m[idx][b]);
            if (dark) { clearBefore = false; break; }
        }
        boolean clearAfter = true;
        for (int k = 7; k <= 10; k++) {
            int idx = (horizontal ? b : a) + k;
            boolean dark = idx < n && (horizontal ? m[a][idx] : m[idx][b]);
            if (dark) { clearAfter = false; break; }
        }
        return clearBefore || clearAfter;
    }

    private static boolean[][] copyMatrix(boolean[][] src) {
        boolean[][] dst = new boolean[src.length][];
        for (int i = 0; i < src.length; i++) {
            dst[i] = src[i].clone();
        }
        return dst;
    }

    private static final class BitBuffer {
        private final byte[] bytes;
        private int length = 0;

        BitBuffer(int maxBits) {
            this.bytes = new byte[(maxBits + 7) / 8 + 1];
        }

        void appendBits(int val, int numBits) {
            for (int i = numBits - 1; i >= 0; i--) {
                if (((val >>> i) & 1) != 0) {
                    bytes[length >>> 3] |= (byte) (1 << (7 - (length & 7)));
                }
                length++;
            }
        }

        byte getByte(int index) {
            return bytes[index];
        }
    }
}
