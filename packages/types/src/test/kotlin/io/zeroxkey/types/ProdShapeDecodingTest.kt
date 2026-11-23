package io.zeroxkey.types

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Hand-written payloads shaped like real 0xkey responses (all identifiers are placeholders).
 * Production omits or nulls message fields that the swagger marks as required.
 */
class ProdShapeDecodingTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `completed activity with null vote user, missing timestamps and null sibling results`() {
        val body = """
            {
              "activity": {
                "id": "activity-00000000",
                "organizationId": "org-00000000",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V7",
                "fingerprint": "fp-00000000",
                "canApprove": false,
                "canReject": false,
                "timestampMs": "1700000000000",
                "votes": [
                  {
                    "id": "vote-00000000",
                    "activityId": "activity-00000000",
                    "userId": "user-00000000",
                    "user": null,
                    "selection": "VOTE_SELECTION_APPROVED",
                    "message": "{}",
                    "publicKey": "02aa",
                    "signature": "3045",
                    "scheme": "SIGNATURE_SCHEME_TK_API_P256"
                  }
                ],
                "result": {
                  "createSubOrganizationResultV7": {
                    "subOrganizationId": "suborg-00000000",
                    "wallet": null,
                    "rootUserIds": ["user-00000000"]
                  },
                  "createWalletResult": null,
                  "signRawPayloadResult": null
                },
                "intent": null,
                "failure": null,
                "unknownServerField": {"nested": true}
              }
            }
        """.trimIndent()

        val activity = json.decodeFromString(TGetActivityResponse.serializer(), body).activity
        assertNull(activity.createdAt)
        assertNull(activity.updatedAt)
        assertNull(activity.intent)
        assertNull(activity.votes.single().user)
        assertEquals("suborg-00000000", activity.result?.createSubOrganizationResultV7?.subOrganizationId)
        assertNull(activity.result?.createWalletResult)
    }

    @Test
    fun `pending activity without result`() {
        val body = """
            {
              "activity": {
                "id": "activity-00000001",
                "organizationId": "org-00000000",
                "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                "fingerprint": "fp-00000001",
                "canApprove": true,
                "canReject": true,
                "timestampMs": "1700000000000",
                "votes": []
              }
            }
        """.trimIndent()

        val activity = json.decodeFromString(V1ActivityResponse.serializer(), body).activity
        assertNull(activity.result)
        assertEquals(V1ActivityStatus.ACTIVITY_STATUS_CONSENSUS_NEEDED, activity.status)
    }

    @Test
    fun `wallet list without timestamps`() {
        val body = """
            {
              "wallets": [
                {"walletId": "wallet-00000000", "walletName": "Default", "exported": false, "imported": false},
                {"walletId": "wallet-00000001", "walletName": "Second", "exported": false, "imported": true,
                 "createdAt": null, "updatedAt": {"seconds": "1700000000", "nanos": "0"}}
              ]
            }
        """.trimIndent()

        val wallets = json.decodeFromString(TGetWalletsResponse.serializer(), body).wallets
        assertEquals(2, wallets.size)
        assertNull(wallets[0].createdAt)
        assertNotNull(wallets[1].updatedAt)
    }

    @Test
    fun `wallet account without timestamps`() {
        val body = """
            {
              "accounts": [
                {
                  "walletAccountId": "account-00000000",
                  "walletId": "wallet-00000000",
                  "organizationId": "org-00000000",
                  "address": "0x0000000000000000000000000000000000000000",
                  "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
                  "curve": "CURVE_SECP256K1",
                  "path": "m/44'/60'/0'/0/0",
                  "pathFormat": "PATH_FORMAT_BIP32"
                }
              ]
            }
        """.trimIndent()

        val account = json.decodeFromString(TGetWalletAccountsResponse.serializer(), body).accounts.single()
        assertNull(account.createdAt)
        assertEquals(V1AddressFormat.ADDRESS_FORMAT_ETHEREUM, account.addressFormat)
    }
}
