package io.zeroxkey.encoding

import io.zeroxkey.encoding.utils.ZeroXKeyEncodingError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Byte-for-byte checks against vectors produced by the 0xkey JS SDK (see FIXTURES.md). */
class EncodingVectorTest {
    private val fixture: JsonObject = Json.parseToJsonElement(
        javaClass.getResource("/fixtures/encoding.json")!!.readText()
    ).jsonObject

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

    @Test
    fun `fixture provenance`() {
        val meta = fixture.getValue("_meta").jsonObject
        assertEquals(40, meta.str("sdk_js_commit").length)
        assertTrue(fixture.getValue("cases").jsonArray.size >= 8)
    }

    @Test
    fun `hex round trip`() {
        for (c in fixture.getValue("cases").jsonArray.map { it.jsonObject }) {
            val bytes = decodeHex(c.str("hex"))
            assertEquals(c.str("hex"), bytes.toHexString())
            assertContentEquals(bytes, decodeHex(c.str("hex").uppercase()))
        }
    }

    @Test
    fun base64url() {
        for (c in fixture.getValue("cases").jsonArray.map { it.jsonObject }) {
            val bytes = decodeHex(c.str("hex"))
            assertEquals(c.str("base64url"), bytes.toBase64Url())
            assertContentEquals(bytes, decodeBase64Url(c.str("base64url")))
            assertFalse(c.str("base64url").contains("="))
        }
        for (c in fixture.getValue("stringToBase64url").jsonArray.map { it.jsonObject }) {
            assertEquals(c.str("base64url"), c.str("input").utf8ToBase64Url())
        }
    }

    @Test
    fun `base58 and base58check`() {
        for (c in fixture.getValue("cases").jsonArray.map { it.jsonObject }) {
            val bytes = decodeHex(c.str("hex"))
            assertEquals(c.str("base58"), base58Encode(bytes))
            assertContentEquals(bytes, base58Decode(c.str("base58")))
            assertEquals(c.str("base58check"), base58CheckEncode(bytes))
            assertContentEquals(bytes, base58CheckDecode(c.str("base58check")))
        }
    }

    @Test
    fun `hex length padding`() {
        for (p in fixture.getValue("hexPadding").jsonArray.map { it.jsonObject }) {
            val padded = decodeHexStrict(p.str("input"), p.getValue("length").jsonPrimitive.int)
            assertEquals(p.str("padded"), padded.toHexString())
        }
        assertFailsWith<ZeroXKeyEncodingError> { decodeHexStrict("abcdef", 2) }
    }

    @Test
    fun `invalid hex rejected like sdk-js`() {
        val invalid = fixture.getValue("invalidHex").jsonArray.map { it.jsonPrimitive.content }
        assertTrue("0x00" in invalid)
        for (s in invalid) {
            assertFailsWith<ZeroXKeyEncodingError>(s) { decodeHexStrict(s) }
        }
    }

    @Test
    fun `base58check rejects corruption`() {
        val good = fixture.getValue("cases").jsonArray[3].jsonObject.str("base58check")
        val corrupted = good.dropLast(1) + if (good.last() == '2') '3' else '2'
        assertFailsWith<ZeroXKeyEncodingError> { base58CheckDecode(corrupted) }
        assertFailsWith<ZeroXKeyEncodingError> { base58Decode("0OIl") }
    }
}
