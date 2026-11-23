package io.zeroxkey.core

import io.zeroxkey.core.internal.utils.ClientSignature
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

/** Client-signature messages checked byte-for-byte against the 0xkey JS SDK (see FIXTURES.md). */
class ClientSignatureVectorTest {
    private val fixture: JsonObject = Json.parseToJsonElement(
        javaClass.getResource("/fixtures/client-signature.json")!!.readText()
    ).jsonObject

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

    @Test
    fun `login message matches sdk-js for token key and session key`() {
        val token = fixture.str("verificationToken")
        val cases = fixture.getValue("loginCases").jsonArray.map { it.jsonObject }
        assertEquals(2, cases.size)
        for (c in cases) {
            val sessionKey = c.getValue("input").jsonObject["sessionPublicKey"]?.jsonPrimitive?.content
            val payload = ClientSignature.forLogin(token, sessionKey)
            assertEquals(c.str("message"), payload.message, c.str("label"))
            assertEquals(c.str("publicKey"), payload.clientSignaturePublicKey, c.str("label"))
        }
    }
}
