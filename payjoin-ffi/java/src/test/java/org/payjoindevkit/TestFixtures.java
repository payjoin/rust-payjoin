package org.payjoindevkit;

import java.util.HexFormat;

/** Shared fixture data for the unit tests in this package. Mirrors Kotlin's {@code TestFixtures.kt}. */
final class TestFixtures {
    private TestFixtures() {
    }

    static final byte[] OHTTP_KEYS_DATA = HexFormat.of().parseHex(
            "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003");
}
