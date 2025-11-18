package com.wnc.createaccount.ui

import android.app.Dialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.os.bundleOf
import androidx.fragment.app.DialogFragment
import androidx.lifecycle.lifecycleScope
import com.wnc.createaccount.R
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Lifecycle-safe success dialog that auto-dismisses and notifies the parent fragment.
 * Sends FragmentResult with requestKey = REQ_SUCCESS_DIALOG when dismissed or confirmed.
 */
class SuccessDialogFragment : DialogFragment() {

    companion object {
        const val TAG = "SuccessDialogFragment"
        const val REQ_SUCCESS_DIALOG = "success_dialog_result"
        const val KEY_CONFIRMED = "confirmed"

        fun newInstance(): SuccessDialogFragment = SuccessDialogFragment()
    }

    private var autoDismissJob: Job? = null

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        // Optional: make the dialog non-title + transparent background from style
        // You can also use a MaterialAlertDialog if you prefer.
        return Dialog(requireContext()).apply {
            setContentView(R.layout.dialog_pairing_success)
            setCancelable(true)
            setCanceledOnTouchOutside(false)

            window?.setBackgroundDrawableResource(android.R.color.transparent)

            // Hook up the confirm button (ensure the ID exists in your layout)
            findViewById<View?>(R.id.btnConfirmOtp)?.setOnClickListener {
                // User explicitly confirmed → dismiss; onDismiss will publish the result.
                dismiss()
            }
        }
    }

    override fun onStart() {
        super.onStart()
        // Resize (optional)
        dialog?.window?.let { w ->
            val lp = w.attributes
            lp.width = (resources.displayMetrics.widthPixels * 0.9f).toInt()
            w.attributes = lp
        }

        // Auto-dismiss after 1500ms, lifecycle-safe
        autoDismissJob?.cancel()
        autoDismissJob = viewLifecycleOwner.lifecycleScope.launch {
            delay(1500)
            // If still showing, dismiss; onDismiss will publish the result.
            if (dialog?.isShowing == true) dismiss()
        }
    }

    override fun onDestroyView() {
        autoDismissJob?.cancel()
        autoDismissJob = null
        super.onDestroyView()
    }

    override fun onDismiss(dialog: android.content.DialogInterface) {
        super.onDismiss(dialog)
        // Notify parent that the dialog finished (either confirmed or auto-dismissed)
        parentFragmentManager.setFragmentResult(
            REQ_SUCCESS_DIALOG,
            bundleOf(KEY_CONFIRMED to true)
        )
    }
}
