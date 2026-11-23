package io.zeroxkey.core.internal

import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.http.ZeroXKeyClient
import io.zeroxkey.passkey.PasskeyRegistrationResult
import io.zeroxkey.passkey.PasskeyUser
import io.zeroxkey.types.TCreateAuthenticatorsBody
import io.zeroxkey.types.V1AuthenticatorParamsV2
import java.util.UUID

internal object PasskeyEnrollment {
    /**
     * Registers a new passkey for [rpId] and submits it as an authenticator of [userId] in
     * [organizationId] through [client] (`ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2`).
     * The WebAuthn user handle is a random UUID, as in `signUpWithPasskey`.
     *
     * @return the new authenticator's ID.
     */
    suspend fun addPasskey(
        client: ZeroXKeyClient,
        rpId: String,
        name: String,
        userId: String,
        organizationId: String,
        register: suspend (user: PasskeyUser, rpId: String) -> PasskeyRegistrationResult,
    ): String {
        val registration = register(
            PasskeyUser(id = UUID.randomUUID().toString(), name = name, displayName = name),
            rpId,
        )
        val res = client.createAuthenticators(
            TCreateAuthenticatorsBody(
                organizationId = organizationId,
                userId = userId,
                authenticators = listOf(
                    V1AuthenticatorParamsV2(
                        authenticatorName = name,
                        challenge = registration.challenge,
                        attestation = registration.attestation,
                    )
                ),
            )
        )
        return res.result.authenticatorIds.firstOrNull()
            ?: throw ZeroXKeyKotlinError.InvalidResponse("create_authenticators returned no authenticatorId")
    }
}
