package io.zeroxkey.core.internal

import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.core.testing.MockGateway
import io.zeroxkey.http.utils.ZeroXKeyHttpError
import io.zeroxkey.stamper.Stamper
import io.zeroxkey.types.V1TransactionType
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class TransactionSigningTest {
    private val gateway = MockGateway()
    private val client = gateway.client(
        Stamper(
            "02af3f78e4b6098bfe26f276eefa5cc009e2b6d85c0510f029a7840fac2cc7f9d5",
            "ccd552e947469a77134e6d0aaa56f05635d5ba2ea249833505e4f036aab043ec",
        )
    )
    private val path = "/api/public/v1/submit/sign_transaction"
    private val unsigned = "02e801808477359400850ba43b740082520894" + "00".repeat(20) + "8080c0"

    @AfterTest
    fun tearDown() = gateway.close()

    private suspend fun sign(tx: String = unsigned) = TransactionSigning.signTransaction(
        client = client,
        organizationId = "org-sub-test",
        signWith = "0x" + "ab".repeat(20),
        unsignedTransaction = tx,
        type = V1TransactionType.TRANSACTION_TYPE_ETHEREUM,
    )

    @Test
    fun `submits sign_transaction v2 and returns the signed transaction`() = runTest {
        gateway.json(path, MockGateway.completedActivity(
            "ACTIVITY_TYPE_SIGN_TRANSACTION_V2", """{"signTransactionResult":{"signedTransaction":"02f86b0180"}}"""))

        assertEquals("02f86b0180", sign())

        val body = Json.parseToJsonElement(gateway.requestsTo(path).single().body!!.utf8()).jsonObject
        assertEquals("ACTIVITY_TYPE_SIGN_TRANSACTION_V2", body.getValue("type").jsonPrimitive.content)
        assertEquals("org-sub-test", body.getValue("organizationId").jsonPrimitive.content)
        val params = body.getValue("parameters").jsonObject
        assertEquals("0x" + "ab".repeat(20), params.getValue("signWith").jsonPrimitive.content)
        assertEquals(unsigned, params.getValue("unsignedTransaction").jsonPrimitive.content)
        assertEquals("TRANSACTION_TYPE_ETHEREUM", params.getValue("type").jsonPrimitive.content)
    }

    @Test
    fun `empty transaction is rejected locally`() = runTest {
        assertFailsWith<ZeroXKeyKotlinError.InvalidParameter> { sign(" ") }
        assertTrue(gateway.requests.isEmpty())
    }

    @Test
    fun `failed activity is a named error`() = runTest {
        gateway.json(path, MockGateway.activityWithStatus("ACTIVITY_TYPE_SIGN_TRANSACTION_V2", "ACTIVITY_STATUS_FAILED"))
        assertFailsWith<ZeroXKeyHttpError.ActivityNotCompleted.Failed> { sign() }
    }
}
