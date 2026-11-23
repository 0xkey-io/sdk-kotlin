package io.zeroxkey.stamper

import io.zeroxkey.encoding.sha256
import io.zeroxkey.stamper.internal.ApiKeyStamper
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assume.assumeTrue
import java.io.File
import kotlin.test.Test

/**
 * Kotlin -> sdk-js direction of the cross-language vectors: writes Kotlin-produced `X-Stamp` headers for
 * verification with sdk-js. Runs only with `-PvectorOut=<dir> -PvectorFixtures=<dir>`.
 */
class StamperVectorEmitter {
    @Test
    fun emit() {
        val out = System.getProperty("zeroxkey.vectorOut").orEmpty()
        val dir = System.getProperty("zeroxkey.vectorFixtures").orEmpty()
        assumeTrue("vector emitter disabled", out.isNotEmpty() && dir.isNotEmpty())
        val cases = Json.parseToJsonElement(File(dir, "api-key-stamp.json").readText()).jsonObject
            .getValue("cases").jsonArray.map { it.jsonObject }
        fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

        val json = buildJsonObject {
            put("apiKeyStamps", buildJsonArray {
                for (c in cases) {
                    val payload = c.str("payload")
                    add(buildJsonObject {
                        put("publicKey", c.str("publicKey"))
                        put("payload", payload)
                        put("stampHeaderValue", ApiKeyStamper.stamp(sha256(payload.toByteArray(Charsets.UTF_8)), c.str("publicKey"), c.str("privateKey")))
                    })
                }
            })
        }
        File(out, "stamper.json").writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), json))
    }
}
