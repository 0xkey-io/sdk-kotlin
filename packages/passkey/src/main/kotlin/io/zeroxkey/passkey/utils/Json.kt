// Modified by 0xkey
package io.zeroxkey.passkey.utils

import io.zeroxkey.encoding.toBase64Url
import kotlinx.serialization.json.JsonArrayBuilder
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

fun buildCreatePublicKeyOptionsJson(
    rpId: String,
    userId: ByteArray,
    userName: String,
    challenge: ByteArray,
    excludeCredentialIds: List<ByteArray>,
    attestation: String = "none" // "none" keeps the flow simple; change if you need full attestation
): String = buildJsonObject {
    putJsonObject("rp") {
        put("id", rpId)
        put("name", rpId)
    }
    putJsonObject("user") {
        put("id", userId.toBase64Url())
        put("name", userName)
        put("displayName", userName)
    }
    put("challenge", challenge.toBase64Url())
    // ES256 only: the 0xkey gateway verifies ES256 passkey signatures and nothing else.
    putJsonArray("pubKeyCredParams") {
        addJsonObject {
            put("type", "public-key")
            put("alg", -7)
        }
    }
    put("timeout", 60000)
    put("attestation", attestation)
    putJsonArray("excludeCredentials") { excludeCredentialIds.forEach { addCredential(it) } }
    putJsonObject("authenticatorSelection") {
        put("residentKey", "preferred")
        put("userVerification", "preferred")
    }
}.toString()

// Build WebAuthn "publicKey" GET options JSON for Credential Manager.
fun buildGetPublicKeyOptionsJson(
    rpId: String,
    challenge: ByteArray,
    allowCredentialIds: List<ByteArray> = emptyList()
): String = buildJsonObject {
    put("challenge", challenge.toBase64Url())
    put("rpId", rpId)
    put("timeout", 60000)
    put("userVerification", "preferred")
    putJsonArray("allowCredentials") { allowCredentialIds.forEach { addCredential(it) } }
}.toString()

private fun JsonArrayBuilder.addCredential(id: ByteArray) = addJsonObject {
    put("type", "public-key")
    put("id", id.toBase64Url())
}
