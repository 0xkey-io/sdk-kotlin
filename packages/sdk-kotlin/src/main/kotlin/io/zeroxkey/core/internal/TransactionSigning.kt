package io.zeroxkey.core.internal

import io.zeroxkey.core.models.errors.ZeroXKeyKotlinError
import io.zeroxkey.http.ZeroXKeyClient
import io.zeroxkey.types.TSignTransactionBody
import io.zeroxkey.types.V1TransactionType

internal object TransactionSigning {
    /**
     * Submits `ACTIVITY_TYPE_SIGN_TRANSACTION_V2` and returns the signed transaction. The
     * unsigned transaction is passed through as given; serialization is the caller's job.
     */
    suspend fun signTransaction(
        client: ZeroXKeyClient,
        organizationId: String,
        signWith: String,
        unsignedTransaction: String,
        type: V1TransactionType,
    ): String {
        if (unsignedTransaction.isBlank()) {
            throw ZeroXKeyKotlinError.InvalidParameter("unsignedTransaction is empty")
        }
        val signed = client.signTransaction(
            TSignTransactionBody(
                organizationId = organizationId,
                signWith = signWith,
                unsignedTransaction = unsignedTransaction,
                type = type,
            )
        ).result.signedTransaction
        if (signed.isEmpty()) throw ZeroXKeyKotlinError.InvalidResponse("sign_transaction returned no signedTransaction")
        return signed
    }
}
