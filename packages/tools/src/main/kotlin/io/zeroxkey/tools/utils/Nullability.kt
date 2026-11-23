package io.zeroxkey.tools.utils

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path

/**
 * Response-side nullability policy (openapi/codegen-policy.json).
 *
 * The gateway serialises unset proto3 sub-messages as `null`, so every message-typed
 * property (a `$ref` to an object definition) on a model or response type is generated as
 * `T? = null` unless an allowlist entry covers it. Scalars, arrays, enums and request
 * bodies keep the swagger `required` semantics.
 */
object NullablePolicy {
    data class Entry(
        val kind: String?,
        val def: String?,
        val property: String?,
        val reason: String,
    ) {
        fun matches(site: Site): Boolean =
            (kind == null || kind == site.kind) &&
                (def == null || def == site.sourceDef) &&
                (property == null || property == site.property)

        fun label(): String = listOfNotNull(
            kind?.let { "kind=$it" },
            def?.let { "def=$it" },
            property?.let { "property=$it" },
        ).joinToString(" ")
    }

    /** A message-typed property that the upstream rule would generate as non-optional. */
    data class Site(
        val kind: String,
        val typeName: String,
        val sourceDef: String,
        val property: String,
    )

    private var entries: List<Entry> = emptyList()
    private var expectedNonOptional: Int = -1
    private var loaded = false

    /** Sites where swagger marks a message property required (upstream: non-optional). */
    val requiredMessageSites = mutableListOf<Site>()

    /** Sites that stay non-optional after applying the policy. */
    val nonOptionalSites = mutableListOf<Pair<Site, Entry>>()

    fun load(path: Path) {
        val root = Json.parseToJsonElement(Files.readString(path)).jsonObject
        expectedNonOptional = root["expectedNonOptionalMessageProperties"]!!.jsonPrimitive.int
        entries = root["allowlist"]!!.jsonArray.map { el ->
            val o = el.jsonObject
            Entry(
                kind = o["kind"]?.jsonPrimitive?.contentOrNull,
                def = o["def"]?.jsonPrimitive?.contentOrNull,
                property = o["property"]?.jsonPrimitive?.contentOrNull,
                reason = o["reason"]!!.jsonPrimitive.content,
            )
        }
        loaded = true
    }

    /** Whether [schema] is a `$ref` to an object (message) definition in [defs]. */
    fun isMessageRef(schema: JsonObject?, defs: Map<String, JsonObject>): Boolean {
        val ref = schemaRefName(schema) ?: return false
        val def = defs[ref] ?: return false
        if ((def["enum"] as? JsonArray)?.isNotEmpty() == true) return false
        val type = def["type"]?.jsonPrimitive?.contentOrNull
        return type == null || type == "object"
    }

    /**
     * Decides whether a required property is non-optional. Returns true when the property
     * stays non-optional (not a message, or covered by the allowlist).
     */
    fun keepRequired(
        kind: String,
        typeName: String,
        sourceDef: String,
        property: String,
        schema: JsonObject?,
        defs: Map<String, JsonObject>,
    ): Boolean {
        check(loaded) { "codegen-policy.json not loaded" }
        if (!isMessageRef(schema, defs)) return true
        val site = Site(kind, typeName, sourceDef, property)
        requiredMessageSites += site
        val entry = entries.firstOrNull { it.matches(site) } ?: return false
        nonOptionalSites += site to entry
        return true
    }

    /** Message properties that are non-optional by construction (not decoded from swagger `required`). */
    val structuralSites = mutableListOf<Site>()

    fun recordStructural(kind: String, typeName: String, sourceDef: String, property: String) {
        val site = Site(kind, typeName, sourceDef, property)
        structuralSites += site
        val entry = entries.firstOrNull { it.matches(site) }
            ?: error("Structural non-optional message property not in allowlist: $site")
        nonOptionalSites += site to entry
    }

    /** Fails generation when the result drifts from the pinned policy. Returns the report text. */
    fun verify(): String {
        val sb = StringBuilder()
        val distinctRequired = requiredMessageSites.distinct()
        val distinctNonOptional = nonOptionalSites.distinctBy { it.first }
        sb.appendLine("nullable policy: swagger-required message properties on models/responses (upstream: non-optional) = ${distinctRequired.size}")
        sb.appendLine("nullable policy: of which still non-optional = ${distinctNonOptional.count { it.first in distinctRequired }}")
        sb.appendLine("nullable policy: structural (client-constructed / oneOf variant) = ${structuralSites.distinct().size}")
        sb.appendLine("nullable policy: non-optional after policy = ${distinctNonOptional.size} (expected ${expectedNonOptional})")
        val errors = mutableListOf<String>()
        entries.forEach { e ->
            val n = distinctNonOptional.count { it.second == e }
            sb.appendLine("  allowlist [${e.label()}] matches $n: ${e.reason}")
            if (n == 0) errors += "allowlist entry matches nothing: ${e.label()}"
        }
        if (distinctNonOptional.size != expectedNonOptional) {
            errors += "non-optional message properties ${distinctNonOptional.size} != expectedNonOptionalMessageProperties $expectedNonOptional"
        }
        if (errors.isNotEmpty()) {
            System.err.println(sb)
            errors.forEach { System.err.println("ERROR: $it") }
            System.err.println("Non-optional sites:")
            distinctNonOptional.forEach { System.err.println("  ${it.first}") }
            throw IllegalStateException("codegen nullable self-check failed")
        }
        return sb.toString()
    }

    fun siteListing(): String = nonOptionalSites.distinctBy { it.first }
        .joinToString("\n") { (s, _) -> "${s.kind}\t${s.typeName}.${s.property}\t(def ${s.sourceDef})" }
}

/**
 * Collects generated model/response classes and emits a JUnit test that decodes each of
 * them from minimal JSON where every nullable message property is (a) `null` and
 * (b) absent.
 */
object NullabilityTestEmitter {
    data class Case(
        val className: String,
        val serializerExpr: String,
        val schema: JsonObject,
        val defs: Map<String, JsonObject>,
        val nullable: Map<String, Boolean>,
        val oneOfVariant: String?,
    )

    val cases = linkedMapOf<String, Case>()

    fun register(case: Case) {
        cases.putIfAbsent(case.className, case)
    }

    private fun quote(s: String) = buildString {
        append('"')
        s.forEach { c ->
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                else -> append(c)
            }
        }
        append('"')
    }

    private fun scalarDefault(schema: JsonObject, defs: Map<String, JsonObject>): String {
        schemaRefName(schema)?.let { ref ->
            val def = defs[ref]
            val enum = def?.get("enum") as? JsonArray
            if (enum != null && enum.isNotEmpty()) return quote(enum.first().jsonPrimitive.content)
        }
        if ((schema["enum"] as? JsonArray)?.isNotEmpty() == true) return "\"\""
        return when (jsonTypeOf(schema)?.lowercase()) {
            "string" -> "\"\""
            "boolean" -> "false"
            "number", "integer" -> "0"
            "array" -> "[]"
            "object" -> "{}"
            else -> "{}"
        }
    }

    private fun minimalJson(caseName: String, mode: String, depth: Int, seen: Set<String>): String {
        val case = cases[caseName] ?: return "{}"
        val props = (case.schema["properties"] as? JsonObject) ?: JsonObject(emptyMap())
        val required = (case.schema["required"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.toSet() ?: emptySet()
        val parts = mutableListOf<String>()
        props.toSortedMap().forEach { (key, el) ->
            val s = el.jsonObject
            val isNullable = case.nullable[key] ?: true
            val isVariant = key == case.oneOfVariant
            when {
                isVariant || (key in required && !isNullable) -> {
                    val value = if (NullablePolicy.isMessageRef(s, case.defs)) {
                        val ref = sanitizeTypeName(schemaRefName(s)!!)
                        if (depth > 8 || ref in seen) "{}" else minimalJson(ref, mode, depth + 1, seen + ref)
                    } else scalarDefault(s, case.defs)
                    parts += "${quote(key)}:$value"
                }
                mode == "null" -> parts += "${quote(key)}:null"
                else -> Unit
            }
        }
        return "{" + parts.joinToString(",") + "}"
    }

    fun write(outDir: Path, pkg: String) {
        val names = cases.keys.toList()
        val chunks = names.chunked(40)
        val sb = StringBuilder()
        sb.appendLine("// @generated by codegen. DO NOT EDIT BY HAND")
        sb.appendLine("package $pkg")
        sb.appendLine()
        sb.appendLine("import kotlinx.serialization.KSerializer")
        sb.appendLine("import kotlinx.serialization.json.Json")
        sb.appendLine("import kotlin.test.Test")
        sb.appendLine()
        sb.appendLine("/** Every generated model/response decodes when nullable message properties are null or absent. */")
        sb.appendLine("class GeneratedNullabilityTest {")
        sb.appendLine("    private val json = Json { ignoreUnknownKeys = true }")
        sb.appendLine()
        sb.appendLine("    private fun <T> check(serializer: KSerializer<T>, vararg bodies: String) {")
        sb.appendLine("        bodies.forEach { body ->")
        sb.appendLine("            try { json.decodeFromString(serializer, body) }")
        sb.appendLine("            catch (e: Exception) { throw AssertionError(\"${'$'}{serializer.descriptor.serialName}: ${'$'}body\", e) }")
        sb.appendLine("        }")
        sb.appendLine("    }")
        sb.appendLine()
        sb.appendLine("    // ${names.size} generated types")
        chunks.forEachIndexed { i, chunk ->
            sb.appendLine()
            sb.appendLine("    @Test")
            sb.appendLine("    fun decodesNullAndMissing_${i + 1}() {")
            chunk.forEach { name ->
                val case = cases.getValue(name)
                val nullBody = minimalJson(name, "null", 0, setOf(name))
                val missingBody = minimalJson(name, "missing", 0, setOf(name))
                sb.appendLine("        check(${case.serializerExpr}, ${kotlinString(nullBody)}, ${kotlinString(missingBody)})")
            }
            sb.appendLine("    }")
        }
        sb.appendLine("}")
        val dir = outDir.resolve(pkg.replace('.', '/'))
        Files.createDirectories(dir)
        Files.writeString(dir.resolve("GeneratedNullabilityTest.kt"), sb.toString())
    }

    private fun kotlinString(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$") + "\""
}
