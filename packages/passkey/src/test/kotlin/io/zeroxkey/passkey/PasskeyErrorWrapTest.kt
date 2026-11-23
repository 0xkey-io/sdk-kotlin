package io.zeroxkey.passkey

import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import io.zeroxkey.passkey.utils.ZeroXKeyPasskeyError
import kotlin.test.Test
import kotlin.test.assertIs

class PasskeyErrorWrapTest {
    @Test
    fun `registration cancel becomes Cancelled`() {
        assertIs<ZeroXKeyPasskeyError.Cancelled>(ZeroXKeyPasskeyError.wrap(CreateCredentialCancellationException("dismissed")))
    }

    @Test
    fun `assertion cancel becomes Cancelled`() {
        assertIs<ZeroXKeyPasskeyError.Cancelled>(ZeroXKeyPasskeyError.wrap(GetCredentialCancellationException("dismissed")))
    }

    @Test
    fun `cancel nested in another passkey error becomes Cancelled`() {
        val nested = ZeroXKeyPasskeyError.RegistrationFailed(CreateCredentialCancellationException("dismissed"))
        assertIs<ZeroXKeyPasskeyError.Cancelled>(ZeroXKeyPasskeyError.wrap(nested))
    }

    @Test
    fun `other failures keep their type`() {
        assertIs<ZeroXKeyPasskeyError.OperationFailed>(ZeroXKeyPasskeyError.wrap(IllegalStateException("x")))
        val decode = ZeroXKeyPasskeyError.DecodeFailed(IllegalStateException("x"))
        assertIs<ZeroXKeyPasskeyError.DecodeFailed>(ZeroXKeyPasskeyError.wrap(decode))
    }
}
