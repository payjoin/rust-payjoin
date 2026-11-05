package org.payjoindevkit

import java.util.HexFormat

internal val ohttpKeysData: ByteArray =
    HexFormat.of().parseHex(
        "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
    )

/** A consensus-encoded transaction with one input and one output. It spends nothing a fresh session holds. */
internal val unrelatedTx: ByteArray =
    HexFormat.of().parseHex(
        "02000000010000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000ffffffff0100000000000000000000000000",
    )
