// Modified by 0xkey
package io.zeroxkey.demo.ui.auth

import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.fragment.app.commit
import androidx.lifecycle.lifecycleScope
import io.zeroxkey.demo.R
import io.zeroxkey.demo.databinding.ComponentAuthCardBinding
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.transition.MaterialSharedAxis
import io.zeroxkey.core.ZeroXKeyContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AuthStepFragment : Fragment(R.layout.component_auth_card) {

    private val vm: AuthSheetViewModel by viewModels({ requireParentFragment() })

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val binding = ComponentAuthCardBinding.bind(view)

        binding.acEmailInput.doOnTextChanged { text, _, _, _ ->
            vm.email.value = text?.toString().orEmpty()
        }

        binding.acSendOtpButton.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                val ok = vm.sendOtpEmail(vm.email.value)
                if (ok) navigateToOtp()
                else binding.acEmailInputLayout.error = "Failed to send code"
            }
        }

        binding.acGoogleOAuthButton.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    ZeroXKeyContext.handleGoogleOAuth(
                        activity = requireActivity(),
                        // secondaryClientIds can also be passed per-call to override the
                        // value configured in OAuthConfig, e.g.:
                        // secondaryClientIds = listOf("<other-client-id>"),
                    )
                    withContext(Dispatchers.Main) { dismissSheetSafely() }
                } catch (t: Throwable) {
                    Log.e("AuthStepFragment", "Failed to handle Google OAuth", t)
                }
            }
        }

        binding.acAppleOAuthButton.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    ZeroXKeyContext.handleAppleOAuth(
                        activity = requireActivity(),
                    )
                    withContext(Dispatchers.Main) { dismissSheetSafely() }
                } catch (t: Throwable) {
                    Log.e("AuthStepFragment", "Failed to handle Apple OAuth", t)
                }
            }
        }

        binding.acTwitterXOAuthButton.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    ZeroXKeyContext.handleXOAuth(
                        activity = requireActivity(),
                    )
                    withContext(Dispatchers.Main) { dismissSheetSafely() }
                } catch (t: Throwable) {
                    Log.e("AuthStepFragment", "Failed to handle X OAuth", t)
                }
            }
        }

        binding.acDiscordOAuthButton.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    ZeroXKeyContext.handleDiscordOAuth(
                        activity = requireActivity(),
                    )
                    withContext(Dispatchers.Main) { dismissSheetSafely() }
                } catch (t: Throwable) {
                    Log.e("AuthStepFragment", "Failed to handle Discord OAuth", t)
                }
            }
        }

         binding.acLoginWithPasskeyButton.setOnClickListener {
             viewLifecycleOwner.lifecycleScope.launch {
                 try {
                     ZeroXKeyContext.loginWithPasskey(
                         activity = requireActivity()
                     )
                     withContext(Dispatchers.Main) { dismissSheetSafely() }
                 } catch (t: Throwable) {
                     Log.e("AuthStepFragment", "Failed to login with passkey", t)
                 }
             }
         }

        binding.acSignUpWithPasskeyButton.setOnClickListener {
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    ZeroXKeyContext.signUpWithPasskey(
                        activity = requireActivity()
                    )
                    withContext(Dispatchers.Main) { dismissSheetSafely() }
                } catch (t: Throwable) {
                    Log.e("AuthStepFragment", "Failed to sign up with passkey", t)
                }
            }
        }
    }

    private fun navigateToOtp() {
        val forward = MaterialSharedAxis(MaterialSharedAxis.X, true)
        val back    = MaterialSharedAxis(MaterialSharedAxis.X, false)

        parentFragment?.childFragmentManager?.commit {
            setReorderingAllowed(true)
            replace(R.id.sheet_container, OtpStepFragment())
            addToBackStack("otp")
        }

        // Also set fragment transitions for nicer Material motion
        enterTransition = forward
        exitTransition = back
        reenterTransition = back
        returnTransition = forward
    }

    private fun dismissSheetSafely() {
        val sheet = (parentFragment as? BottomSheetDialogFragment) ?: return
        // Always commit on main to avoid background-thread fragment ops.
        requireActivity().runOnUiThread {
            val fm = sheet.parentFragmentManager
            if (!sheet.isAdded) return@runOnUiThread
            if (fm.isStateSaved) sheet.dismissAllowingStateLoss() else sheet.dismiss()
        }
    }
}