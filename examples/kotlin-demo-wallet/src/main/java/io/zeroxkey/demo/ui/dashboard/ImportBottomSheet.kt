// Modified by 0xkey
package io.zeroxkey.demo.ui.dashboard

import android.os.Bundle
import android.util.Log
import android.view.*
import android.widget.FrameLayout
import androidx.core.widget.doOnTextChanged
import androidx.lifecycle.lifecycleScope
import io.zeroxkey.demo.databinding.ComponentImportBinding
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import io.zeroxkey.core.ZeroXKeyContext
import io.zeroxkey.types.V1AddressFormat
import io.zeroxkey.types.V1Curve
import io.zeroxkey.types.V1PathFormat
import io.zeroxkey.types.V1WalletAccountParams
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class ImportBottomSheet : BottomSheetDialogFragment() {
    override fun getTheme(): Int =
        com.google.android.material.R.style.ThemeOverlay_Material3_BottomSheetDialog
    private val mnemonic = MutableStateFlow("")
    private val name = MutableStateFlow("")
    private var _binding: ComponentImportBinding? = null
    private val binding get() = _binding!!

    companion object { fun newInstance(): ImportBottomSheet = ImportBottomSheet() }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = ComponentImportBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        binding.etMnemonic.doOnTextChanged { text, _, _, _ ->
            mnemonic.value = text?.toString().orEmpty()
        }
        binding.etWalletName.doOnTextChanged { text, _, _, _ ->
            name.value = text?.toString().orEmpty()
        }

        binding.btnImport.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val m = mnemonic.value
                    if (m.isEmpty()) return@launch
                    val walletName = name.value.ifBlank { "Wallet-${System.currentTimeMillis()}" }

                    val accounts = listOf(
                        V1WalletAccountParams(
                            addressFormat = V1AddressFormat.ADDRESS_FORMAT_ETHEREUM,
                            curve = V1Curve.CURVE_SECP256K1,
                            path = "m/44'/60'/0'/0/0",
                            pathFormat = V1PathFormat.PATH_FORMAT_BIP32
                        ),
                        V1WalletAccountParams(
                            addressFormat = V1AddressFormat.ADDRESS_FORMAT_SOLANA,
                            curve = V1Curve.CURVE_ED25519,
                            path = "m/44'/501'/0'/0'",
                            pathFormat = V1PathFormat.PATH_FORMAT_BIP32
                        )
                    )

                    ZeroXKeyContext.importWallet(
                        walletName = walletName,
                        mnemonic = m,
                        accounts = accounts
                    )
                    dismiss()
                } catch (t: Throwable) {
                    Log.e("Import", "Import Failed", t)
                }
            }
        }
        binding.btnClose.setOnClickListener { dismiss() }
    }

    override fun onStart() {
        super.onStart()
        val sheet =
            dialog?.findViewById<FrameLayout>(com.google.android.material.R.id.design_bottom_sheet)
        sheet?.let {
            BottomSheetBehavior.from(it).apply {
                state = BottomSheetBehavior.STATE_EXPANDED
                skipCollapsed = true
            }
        }
        dialog?.window?.setDimAmount(0.2f)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}

