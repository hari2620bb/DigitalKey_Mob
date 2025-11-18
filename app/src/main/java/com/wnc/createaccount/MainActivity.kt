package com.wnc.createaccount

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.wnc.createaccount.ui.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

         if (savedInstanceState == null) openFragment(LoginFragment())
//        if (savedInstanceState == null) openFragment(PairingBondingFragment())
    }

    private fun openFragment(fragment: androidx.fragment.app.Fragment, addToBackStack: Boolean = true) {
        val transaction = supportFragmentManager.beginTransaction()
            .setCustomAnimations(
                android.R.anim.fade_in, android.R.anim.fade_out,
                android.R.anim.fade_in, android.R.anim.fade_out
            )
            .replace(R.id.fragment_container, fragment)

        if (addToBackStack) transaction.addToBackStack(null)
        transaction.commit()
    }

    fun openLoginFragment() = openFragment(LoginFragment())
    fun openSignUpFragment() = openFragment(SignUpFragment())
    fun openAddVehicleFragment() = openFragment(AddVehicleFragment())
    fun openHomeFragment() = openFragment(HomeFragment(), addToBackStack = false)
    fun openPairingBondingFragment() = openFragment(PairingBondingFragment())
    fun openPairingBondingKeyFragment() = openFragment(PairingBondingKeyFragment())
    fun openPairingKeyExchangeFragment() = openFragment(PairingKeyExchangeFragment())
    fun openLandingFragment() = openFragment(LandingFragment(), addToBackStack = false)
}
