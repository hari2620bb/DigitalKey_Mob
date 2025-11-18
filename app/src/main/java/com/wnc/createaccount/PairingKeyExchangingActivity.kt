package com.wnc.createaccount

import android.app.Dialog
import android.content.Intent
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.Window
import android.view.WindowManager
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wnc.createaccount.ui.LandingFragment
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class PairingKeyExchangingActivity : AppCompatActivity() {

    private var successDialog: Dialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing_key_exchanging)

        // Start your exchanging animation/work here...

        // Show success after ~3.5s, but only if we are still RESUMED (visible)
        lifecycleScope.launch {
            delay(3500)
            if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) {
                showPairingSuccessDialog()
            }
        }
    }

    private fun showPairingSuccessDialog() {
        successDialog = Dialog(this).apply {
            requestWindowFeature(Window.FEATURE_NO_TITLE)
            setContentView(R.layout.dialog_pairing_success)
            setCancelable(true)
            setCanceledOnTouchOutside(false)

            window?.apply {
                setBackgroundDrawable(ColorDrawable(android.graphics.Color.TRANSPARENT))
                val lp = WindowManager.LayoutParams()
                lp.copyFrom(attributes)
                lp.width = (resources.displayMetrics.widthPixels * 0.9f).toInt()
                attributes = lp
            }

            // If your dialog has a button (e.g. @id/btnDone), wire it:
            findViewById<View?>(R.id.btnConfirmOtp)?.setOnClickListener {
                dismiss()
                // OPTIONAL: go to next page, e.g. ManageKeyActivity or KeyDetailsActivity
                // startActivity(Intent(this@PairingKeyExchangingActivity, ManageKeyActivity::class.java))
                // finish() // if you don't want to come back here
            }
        }
        successDialog?.show()

        // OPTIONAL: auto-dismiss + navigate after a short delay
         lifecycleScope.launch {
             delay(1500)
             if (successDialog?.isShowing == true) {
                 successDialog?.dismiss()
                 startActivity(Intent(this@PairingKeyExchangingActivity, LandingFragment::class.java))
                 finish()
             }
         }

    }

    override fun onDestroy() {
        successDialog?.dismiss() // avoid window leaks
        successDialog = null
        super.onDestroy()
    }
}
