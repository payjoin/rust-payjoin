package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class UriTests {
    @Test
    fun urlEncodedPayjoinParameter() {
        val endpoint = "https://example.com/pj?ciao=1"
        val encodedPj = "https%3A%2F%2Fexample.com%2Fpj%3Fciao%3D1"
        val uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=$encodedPj"
        Uri.parse(uri).use { parsed ->
            assertEquals("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", parsed.address())
            assertEquals(100_000_000uL, parsed.amountSats())
            parsed.checkPjSupported().use { pjUri ->
                assertEquals(endpoint, pjUri.pjEndpoint())
            }
        }
    }

    @Test
    fun missingAmountShouldBeOk() {
        val uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj"
        Uri.parse(uri).use { assertNotNull(it) }
    }

    @Test
    fun validUrisWithDifferentAddressesAndEndpoints() {
        val https = exampleUrl()
        val onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion"
        val addresses = listOf(
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
            "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4",
            "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
        )
        for (address in addresses) {
            for (pj in listOf(https, onion)) {
                Uri.parse("$address?amount=1&pj=$pj").use { assertNotNull(it) }
            }
        }
    }

    @Test
    fun uriParseSmoke() {
        Uri.parse("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").use { uri ->
            assertNotNull(uri.address())
        }
        assertFailsWith<UriParseException> { Uri.parse("not-a-uri") }
    }
}
