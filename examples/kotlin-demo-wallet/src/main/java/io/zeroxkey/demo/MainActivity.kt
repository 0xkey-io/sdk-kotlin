// Modified by 0xkey
package io.zeroxkey.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.Group
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.zeroxkey.demo.databinding.ActivityMainBinding
import io.zeroxkey.demo.ui.auth.AuthBottomSheet
import io.zeroxkey.demo.ui.dashboard.DashboardFragment
import io.zeroxkey.core.ZeroXKeyContext
import io.zeroxkey.core.models.AuthState
import kotlinx.coroutines.launch

private fun Group.setVisible(visible: Boolean) {
    this.visibility = if (visible) android.view.View.VISIBLE else android.view.View.GONE
}
private fun android.view.View.setVisible(visible: Boolean) {
    this.visibility = if (visible) android.view.View.VISIBLE else android.view.View.GONE
}

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var dashboardAttached = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.authComponentButton.setOnClickListener {
            AuthBottomSheet.newInstance().show(supportFragmentManager, "auth")
        }
        binding.logoutButton.setOnClickListener {
            lifecycleScope.launch { ZeroXKeyContext.clearSession() }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    ZeroXKeyContext.authState.collect { state ->
                        render(state)
                    }
                }
            }
        }
    }

    private fun render(state: AuthState) {
        when (state) {
            AuthState.loading -> {
                binding.progress.setVisible(true)
                binding.groupUnauthed.setVisible(false)
                binding.groupAuthed.setVisible(false)
            }
            AuthState.unauthenticated -> {
                binding.progress.setVisible(false)
                binding.groupUnauthed.setVisible(true)
                binding.groupAuthed.setVisible(false)
                if (dashboardAttached) {
                    supportFragmentManager.findFragmentByTag("dashboard")
                        ?.let { supportFragmentManager.beginTransaction().remove(it).commitNowAllowingStateLoss() }
                    dashboardAttached = false
                }
            }
            AuthState.authenticated -> {
                binding.progress.setVisible(false)
                binding.groupUnauthed.setVisible(false)
                binding.groupAuthed.setVisible(true)
                attachDashboardIfNeeded()
            }
        }
    }

    private fun attachDashboardIfNeeded() {
        if (dashboardAttached) return
        supportFragmentManager.beginTransaction()
            .replace(R.id.dashboardContainer, DashboardFragment(), "dashboard")
            .commitNowAllowingStateLoss()
        dashboardAttached = true
    }
}
