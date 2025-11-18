package com.wnc.createaccount

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import com.google.android.material.bottomnavigation.BottomNavigationView

class PairingBondingActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_VIN = "extra_vin" // if you passed VIN earlier
    }

    @SuppressLint("MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing_bonding)
        val bottomNav = findViewById<BottomNavigationView>(R.id.bottom_navigation)


        loadFragment(HomeFragment())
        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_key -> loadFragment(HomeFragment())
                R.id.nav_share -> loadFragment(ShareFragment())
                R.id.nav_key -> loadFragment(KeyFragment())
                R.id.nav_settings -> loadFragment(ProfileFragment())
            }
            true
        }
    }

    private fun loadFragment(fragment: Fragment) {
        supportFragmentManager.commit {
            setReorderingAllowed(true)
            replace(R.id.nav_host_fragment, fragment)
        }
    }
}