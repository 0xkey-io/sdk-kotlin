// Modified by 0xkey
package io.zeroxkey.passkey

import io.zeroxkey.encoding.decodeBase64Url
import io.zeroxkey.encoding.toBase64Url
import io.zeroxkey.passkey.utils.buildCreatePublicKeyOptionsJson
import io.zeroxkey.passkey.utils.buildGetPublicKeyOptionsJson
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebAuthnOptionsBuilderTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun buildCreatePublicKeyOptionsJson_has_expected_fields_and_values() {
        val rpId = "example.com"
        val userId = "user-123".toByteArray()
        val userName = "alice"
        val challenge = ByteArray(32) { it.toByte() }
        val exclude = listOf(byteArrayOf(1,2,3))

        val s = buildCreatePublicKeyOptionsJson(
            rpId = rpId,
            userId = userId,
            userName = userName,
            challenge = challenge,
            excludeCredentialIds = exclude
        )

        val root = json.parseToJsonElement(s).jsonObject

        assertEquals(rpId, root["rp"]!!.jsonObject["id"]!!.jsonPrimitive.content)
        assertEquals(userName, root["user"]!!.jsonObject["name"]!!.jsonPrimitive.content)
        assertEquals(
            json.parseToJsonElement("""[{"type":"public-key","alg":-7}]"""),
            root["pubKeyCredParams"],
        )
        assertEquals("none", root["attestation"]!!.jsonPrimitive.content)

        val challB64 = root["challenge"]!!.jsonPrimitive.content
        val decodedChallenge = decodeBase64Url(challB64)
        assertTrue(decodedChallenge.contentEquals(challenge))

        val excludeArr = root["excludeCredentials"]!!.toString()
        assertTrue(excludeArr.contains("public-key"))
        assertTrue(excludeArr.contains(byteArrayOf(1,2,3).toBase64Url()))
    }

    @Test
    fun names_with_quotes_and_backslashes_stay_valid_json() {
        val name = "Work \"phone\" \\ 2"
        val s = buildCreatePublicKeyOptionsJson(
            rpId = "example.com",
            userId = "u".toByteArray(),
            userName = name,
            challenge = ByteArray(32),
            excludeCredentialIds = emptyList(),
        )
        val user = json.parseToJsonElement(s).jsonObject["user"]!!.jsonObject
        assertEquals(name, user["name"]!!.jsonPrimitive.content)
        assertEquals(name, user["displayName"]!!.jsonPrimitive.content)
    }

    @Test
    fun buildGetPublicKeyOptionsJson_allows_multiple_allowed_ids() {
        val rpId = "example.com"
        val c = ByteArray(32) { (255 - it).toByte() }
        val allow = listOf(
            ByteArray(16) { it.toByte() },
            ByteArray(16) { (it + 1).toByte() }
        )

        val s = buildGetPublicKeyOptionsJson(
            rpId = rpId,
            challenge = c,
            allowCredentialIds = allow
        )

        val root = json.parseToJsonElement(s).jsonObject
        assertEquals(rpId, root["rpId"]!!.jsonPrimitive.content)

        val challB64 = root["challenge"]!!.jsonPrimitive.content
        assertTrue(decodeBase64Url(challB64).contentEquals(c))

        val allowStr = root["allowCredentials"]!!.toString()
        assertTrue(allowStr.contains(allow[0].toBase64Url()))
        assertTrue(allowStr.contains(allow[1].toBase64Url()))
    }
}
