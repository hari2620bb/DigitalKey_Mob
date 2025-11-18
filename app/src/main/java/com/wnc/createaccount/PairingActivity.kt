package com.wnc.createaccount

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class PairingActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_VIN = "extra_vin"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing) // your OTP layout

        val confirms = findViewById<View>(R.id.btnConfirmOtp)
        val et1 = findViewById<EditText>(R.id.etOtp1)
        val et2 = findViewById<EditText>(R.id.etOtp2)
        val et3 = findViewById<EditText>(R.id.etOtp3)
        val et4 = findViewById<EditText>(R.id.etOtp4)
        val et5 = findViewById<EditText>(R.id.etOtp5)
        val et6 = findViewById<EditText>(R.id.etOtp6)

        confirms.setOnClickListener {
            val otp = listOf(et1, et2, et3, et4, et5, et6).joinToString("") { it.text.toString().trim() }
            if (otp.length != 6) {
                Toast.makeText(this, "Enter 6-digit OTP", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val vin = intent.getStringExtra(EXTRA_VIN)
            startActivity(
                Intent(this, PairingKeyExchangingActivity::class.java)
                    .putExtra(PairingBondingActivity.EXTRA_VIN, vin)
            )
            // Optional: close OTP screen so Back doesn't return here
            // finish()
        }
    }
}
