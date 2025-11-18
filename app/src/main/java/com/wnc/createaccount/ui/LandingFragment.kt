package com.wnc.createaccount.ui

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.wnc.createaccount.HomeFragment
import com.wnc.createaccount.KeyFragment
import com.wnc.createaccount.ProfileFragment
import com.wnc.createaccount.R
import com.wnc.createaccount.ShareFragment
import com.wnc.createaccount.databinding.FragmentLandingBinding
import com.wnc.createaccount.models.UserVehicleItem
import com.wnc.createaccount.net.ApiClient
import com.wnc.createaccount.utils.BleUtils
import kotlinx.coroutines.launch
import org.json.JSONObject
import retrofit2.HttpException
import android.graphics.PorterDuff
import com.wnc.createaccount.util.PairingStore

// Top of class
private var prefsListener: SharedPreferences.OnSharedPreferenceChangeListener? = null

class LandingFragment : Fragment() {

    private var _binding: FragmentLandingBinding? = null
    private val binding get() = _binding!!

    private enum class ConnState { PAIRING, CONNECTED, DISCONNECTED }

    private fun chipStateFromFlags(pending: Boolean, connected: Boolean): ConnState =
        when {
            connected -> ConnState.CONNECTED
            pending && !connected -> ConnState.PAIRING
            else -> ConnState.DISCONNECTED
        }

    private fun renderChip(row: View, state: ConnState) {
        val tv = row.findViewById<TextView>(R.id.tvLabel)
        val dot = row.findViewById<ImageView?>(R.id.imgIcon) // optional tint
        when (state) {
            ConnState.CONNECTED -> {
                tv.text = "Connected"
                tv.setTextColor(0xFF2ECC71.toInt()) // green
                dot?.setColorFilter(0xFF2ECC71.toInt(), PorterDuff.Mode.SRC_IN)
                row.isActivated = true
            }
            ConnState.PAIRING -> {
                tv.text = "Pairing…"
                tv.setTextColor(0xFFF39C12.toInt()) // amber
                dot?.setColorFilter(0xFFF39C12.toInt(), PorterDuff.Mode.SRC_IN)
                row.isActivated = false
            }
            ConnState.DISCONNECTED -> {
                tv.text = "Disconnected"
                tv.setTextColor(0xFFE74C3C.toInt()) // red
                dot?.setColorFilter(0xFFE74C3C.toInt(), PorterDuff.Mode.SRC_IN)
                row.isActivated = false
            }
        }
    }

    private fun refreshConnectionStatus(root: View) {
        val btRow = root.findViewById<View>(R.id.itemBt)
        val uwbRow = root.findViewById<View>(R.id.itemUwb)

        val pending = PairingStore.isPending(requireContext())
        val connected = PairingStore.isConnected(requireContext())

        val state = chipStateFromFlags(pending, connected)
        renderChip(btRow, state)
        renderChip(uwbRow, state)
    }


    // ---- Helper to swap CHILD fragments inside Landing ----
    private fun loadChild(fragment: Fragment, tag: String) {
        val fm = childFragmentManager
        val existing = fm.findFragmentByTag(tag)
        val tx = fm.beginTransaction().setReorderingAllowed(true)

        // Hide others, show or add the requested one (simple tab manager)
        fm.fragments.forEach { tx.hide(it) }
        if (existing == null) {
            tx.add(R.id.landing_child_container, fragment, tag)
        } else {
            tx.show(existing)
        }
        tx.commit()
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLandingBinding.inflate(inflater, container, false)
        return binding.root
    }
    override fun onResume() {
        super.onResume()
        _binding?.contentRoot?.let { refreshConnectionStatus(it) }
    }


    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // --- status chips UI ---
        setupStatusChips(root = binding.contentRoot)

        // --- Pairing button ---
        binding.btnPairing.setOnClickListener {
            if (!BleUtils.allPermissionsGranted(requireContext())) {
                BleUtils.requestPermissions(requireActivity() as Activity, 101)
            }
            // Immediately reflect pairing state
            PairingStore.setPending(requireContext(), true)
            PairingStore.setConnected(requireContext(), false)
            refreshConnectionStatus(binding.contentRoot)

            parentFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, PairingBondingFragment())
                .addToBackStack("pairing_bonding")
                .commit()
        }


        // --- Bottom Navigation wiring (child fragments inside Landing) ---
        val bottomNav: BottomNavigationView = binding.bottomNav

        // Load default tab once (e.g., Home)
        if (savedInstanceState == null) {
            loadChild(HomeFragment(), "home")
            bottomNav.selectedItemId = R.id.nav_key   // <-- use your actual menu id for Home
        }

        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_status -> {
                    loadChild(HomeFragment(), "home"); true
                }
                R.id.nav_share -> {
                    loadChild(ShareFragment(), "share"); true
                }
                R.id.nav_map -> {
                    loadChild(ShareFragment(), "map"); true
                }
                R.id.nav_key -> {
                    loadChild(KeyFragment(), "key"); true
                }
                R.id.nav_settings -> {
                    loadChild(ProfileFragment(), "settings"); true
                }
                else -> false
            }
        }


        // --- Auth + fetch flow (unchanged) ---
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val jwt = sp.getString("jwt", null)
        val userId = sp.getString("userId", null)
        val lastVin = sp.getString("last_vin", null)
        val appSp = requireContext().getSharedPreferences("pairing_prefs", Context.MODE_PRIVATE)
// Listen only to the keys PairingStore writes
        prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == "pending" || key == "connected") {
                _binding?.contentRoot?.let { refreshConnectionStatus(it) }
            }
        }
        appSp.registerOnSharedPreferenceChangeListener(prefsListener)

        renderUserVehicleFromPrefs(sp)

        if (jwt.isNullOrBlank() || userId.isNullOrBlank()) {
            openSignUp(); return
        }

        viewLifecycleOwner.lifecycleScope.launch {
            if (!lastVin.isNullOrBlank() && fetchAndPersistUserVin(sp, jwt, userId, lastVin)) {
                return@launch
            }

            val list = tryGetUserVehicles(jwt, userId)
            if (list.isNotEmpty()) {
                val chosenVin = list.first().vin
                sp.edit().putString("last_vin", chosenVin).apply()
                fetchAndPersistUserVin(sp, jwt, userId, chosenVin)
            } else openAddVehicle()
        }
    }

    private fun renderUserVehicleFromPrefs(sp: SharedPreferences) {
        // Reads what you persist in fetchAndPersistUserVin(...)
        val json = sp.getString("last_vehicle_json", null) ?: return
        try {
            val obj = JSONObject(json)

            val name  = obj.optString("name")              // "pravin"
            val vin   = obj.optString("vin")               // "5FNYF4H97EB023456"
            val model = obj.optString("model")             // "Maverick"
            val year  = obj.optInt("year", 0)              // 2025 (optional)
            val image = obj.optString("image_url")         // "scooty-5.png"

            // Header
            view?.findViewById<TextView>(R.id.tvUserName)?.text =
                if (name.isNullOrBlank()) "User" else name

            // Vehicle card
            view?.findViewById<TextView>(R.id.tvVehicleName)?.text =
                if (model.isNullOrBlank()) "My Vehicle" else model

            // Example details line: "<VIN> | <Model> <Year>"
            val details = buildString {
                if (!vin.isNullOrBlank()) append(vin)
                if (!model.isNullOrBlank() || year > 0) {
                    if (isNotEmpty()) append(" | ")
                    append(model)
                    if (year > 0) append(" ").append(year)
                }
            }
            view?.findViewById<TextView>(R.id.tvVehicleDetails)?.text =
                if (details.isEmpty()) "—" else details

            // Optional: set scooter image (resource name or remote URL)
            val img = view?.findViewById<ImageView>(R.id.imgScooter)
            if (!image.isNullOrBlank() && img != null) {
                // Try a local drawable first (strip extension, look up by name)
                val resName = image.substringBeforeLast('.')
                val resId = resources.getIdentifier(resName, "drawable", requireContext().packageName)
                if (resId != 0) {
                    img.setImageResource(resId)
                } else {
                    // If it's a URL, you can use Glide/Picasso. Example with Glide (add dependency):
                    // Glide.with(this).load(image).into(img)
                }
            }
        } catch (_: Exception) {
            // ignore bad JSON
        }
    }


    // ---------- UI helpers ----------
    private fun setupStatusChips(root: View) {
        val itemBt = root.findViewById<View>(R.id.itemBt)
        val itemUwb = root.findViewById<View>(R.id.itemUwb)
        val itemEdit = root.findViewById<View>(R.id.itemEdit)

        itemBt.findViewById<ImageView>(R.id.imgIcon).setImageResource(R.drawable.ic_bluetooth)
        itemUwb.findViewById<ImageView>(R.id.imgIcon).setImageResource(R.drawable.ic_uwb)
        itemEdit.findViewById<ImageView>(R.id.imgIcon).setImageResource(R.drawable.ic_edit)
        itemEdit.findViewById<TextView>(R.id.tvLabel).text = "Edit Details"

        // paint initial status from flags
        refreshConnectionStatus(root)
    }

    // ---------- Networking ----------
    private suspend fun fetchAndPersistUserVin(
        sp: SharedPreferences,
        jwt: String?,
        userId: String?,
        vin: String
    ): Boolean = try {
        val resp = ApiClient.api.getUserVin("Bearer $jwt", userId, vin)
        if (resp.isSuccessful) {
            val item = resp.body()?.response?.firstOrNull()
            if (item != null) {
                val json = JSONObject().apply {
                    put("user_id", item.user_id)
                    put("name", item.name)
                    put("email", item.email)
                    put("country_code", item.country_code)
                    put("phone_number", item.phone_number)
                    put("vin", item.vin)
                    put("model", item.model)
                    put("year", item.year)
                    put("image_url", item.image_url)
                }.toString()
                sp.edit()
                    .putString("last_vin", vin)
                    .putString("last_vehicle_json", json)
                    .apply()

                // 👉 immediately repaint UI
                renderUserVehicleFromPrefs(sp)
                true
            } else false
        } else false
    } catch (_: HttpException) { false } catch (_: Exception) { false }


    private suspend fun tryGetUserVehicles(jwt: String?, userId: String?): List<UserVehicleItem> = try {
        val resp = ApiClient.api.getUserVehicles("Bearer $jwt", userId)
        if (resp.isSuccessful) resp.body()?.response.orEmpty() else emptyList()
    } catch (_: Exception) { emptyList() }

    // ---------- Navigation to other top-level screens ----------
    private fun openSignUp() {
        parentFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, SignUpFragment())
            .addToBackStack(null)
            .commit()
    }

    private fun openAddVehicle() {
        if (!isAdded || view == null || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        // resolve the real container at runtime
        val containerId = (view?.parent as? ViewGroup)?.id ?: return
        parentFragmentManager.commit {
            setReorderingAllowed(true)
            replace(containerId, AddVehicleFragment())
            addToBackStack("add-vehicle")
        }
    }


    private fun openPairingBonding() {
        parentFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, PairingBondingFragment())
            .addToBackStack("pairing_bonding")
            .commit()
    }

    private fun toast(msg: String) =
        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()

    override fun onDestroyView() {
        requireContext()
            .getSharedPreferences("pairing_prefs", Context.MODE_PRIVATE)
            .unregisterOnSharedPreferenceChangeListener(prefsListener)
        prefsListener = null
        _binding = null
        super.onDestroyView()
    }

}
