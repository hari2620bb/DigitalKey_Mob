package com.wnc.createaccount.ui

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.graphics.PorterDuff
import android.os.Bundle
import android.util.Log
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
import com.wnc.createaccount.*
import com.wnc.createaccount.databinding.FragmentLandingBinding
import com.wnc.createaccount.models.UserVehicleItem
import com.wnc.createaccount.net.ApiClient
import com.wnc.createaccount.util.PairingStore
import com.wnc.createaccount.utils.BleUtils
import kotlinx.coroutines.launch
import org.json.JSONObject
import retrofit2.HttpException

class LandingFragment : Fragment() {

    private var _binding: FragmentLandingBinding? = null
    private val binding get() = _binding!!

    // prefs listener for pairing status
    private var prefsListener: SharedPreferences.OnSharedPreferenceChangeListener? = null

    // ---------- Connection chip state ----------

    private enum class ConnState { PAIRING, CONNECTED, DISCONNECTED }

    private fun chipStateFromFlags(pending: Boolean, connected: Boolean): ConnState =
        when {
            connected -> ConnState.CONNECTED
            pending && !connected -> ConnState.PAIRING
            else -> ConnState.DISCONNECTED
        }

    private fun renderChip(row: View, state: ConnState) {
        val tv = row.findViewById<TextView>(R.id.tvLabel)
        val dot = row.findViewById<ImageView?>(R.id.imgIcon)

        when (state) {
            ConnState.CONNECTED -> {
                tv.text = "Connected"
                tv.setTextColor(0xFF2ECC71.toInt())           // green
                dot?.setColorFilter(0xFF2ECC71.toInt(), PorterDuff.Mode.SRC_IN)
                row.isActivated = true
            }
            ConnState.PAIRING -> {
                tv.text = "Pairing…"
                tv.setTextColor(0xFFF39C12.toInt())           // amber
                dot?.setColorFilter(0xFFF39C12.toInt(), PorterDuff.Mode.SRC_IN)
                row.isActivated = false
            }
            ConnState.DISCONNECTED -> {
                tv.text = "Disconnected"
                tv.setTextColor(0xFFE74C3C.toInt())           // red
                dot?.setColorFilter(0xFFE74C3C.toInt(), PorterDuff.Mode.SRC_IN)
                row.isActivated = false
            }
        }
    }

    private fun isVehicleConnected(): Boolean {
        val appCtx = requireActivity().applicationContext
        return PairingStore.isConnected(appCtx)
    }

    private fun updateControlToggles() {
        val connected = isVehicleConnected()

        // Enable toggles only when connected
        binding.toggleEngine.isEnabled = connected
        binding.toggleBike.isEnabled = connected

        // Dim the cards when not connected
        binding.btnEngine.alpha = if (connected) 1f else 0.5f
        binding.btnBike.alpha = if (connected) 1f else 0.5f
    }

    private fun refreshConnectionStatus(root: View) {
        val btRow = root.findViewById<View>(R.id.itemBt)

        val appCtx = requireActivity().applicationContext
        val pending = PairingStore.isPending(appCtx)
        val connected = PairingStore.isConnected(appCtx)

        val state = chipStateFromFlags(pending, connected)
        renderChip(btRow, state)

        // 🔐 also update toggles based on connection
        updateControlToggles()
    }

    // ---------- Child / landing switching ----------

    /** Show original scooter landing UI */
    private fun showLanding() {
        binding.nestedScroll.visibility = View.VISIBLE
        binding.landingChildContainer.visibility = View.GONE
    }

    /** Show a child fragment inside landing_child_container */
    private fun showChild(fragment: Fragment, tag: String) {
        binding.nestedScroll.visibility = View.GONE
        binding.landingChildContainer.visibility = View.VISIBLE

        childFragmentManager.beginTransaction()
            .setReorderingAllowed(true)
            .replace(R.id.landing_child_container, fragment, tag)
            .commit()
    }

    // ---------- Fragment lifecycle ----------

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
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

            // immediately reflect pairing state
            PairingStore.setPending(requireContext(), true)
            PairingStore.setConnected(requireContext(), false)
            refreshConnectionStatus(binding.contentRoot)

            parentFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, PairingBondingFragment())
                .addToBackStack("pairing_bonding")
                .commit()
        }

        // ---------- Bottom Navigation (inside Landing) ----------
        val bottomNav: BottomNavigationView = binding.bottomNav

        if (savedInstanceState == null) {
            // default tab -> Key (landing)
            showLanding()
            bottomNav.selectedItemId = R.id.nav_key
        }

        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_key -> {
                    // show original scooter landing UI
                    showLanding()
                    true
                }
                R.id.nav_status -> {
                    showChild(HomeFragment(), "home")
                    true
                }
                R.id.nav_share -> {
                    showChild(ShareFragment(), "share")
                    true
                }
                R.id.nav_map -> {
                    // TODO: replace with real Map fragment
                    showChild(ShareFragment(), "map")
                    true
                }
                R.id.nav_settings -> {
                    showChild(ProfileFragment(), "settings")
                    true
                }
                else -> false
            }
        }
        // Engine card click
        binding.btnEngine.setOnClickListener {
            if (!isVehicleConnected()) {
                toast("Pair your vehicle first to control engine")
                return@setOnClickListener
            }

            // Toggle checkbox manually when connected
            binding.toggleEngine.isChecked = !binding.toggleEngine.isChecked

            // TODO: send engine start/stop command here
        }

// Steering/Bike card click
        binding.btnBike.setOnClickListener {
            if (!isVehicleConnected()) {
                toast("Pair your vehicle first to unlock steering")
                return@setOnClickListener
            }

            // Toggle checkbox manually when connected
            binding.toggleBike.isChecked = !binding.toggleBike.isChecked

            // TODO: send steering lock/unlock command here
        }


        // ---------- Auth + vehicle fetching ----------

        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val jwt = sp.getString("jwt", null)
        val userId = sp.getString("userId", null)
        val lastVin = sp.getString("last_vin", null)

        val appCtx = requireActivity().applicationContext
        val appSp = appCtx.getSharedPreferences("pairing_prefs", Context.MODE_PRIVATE)

        prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == "pending" || key == "connected") {
                _binding?.contentRoot?.let { refreshConnectionStatus(it) }
            }
        }
        appSp.registerOnSharedPreferenceChangeListener(prefsListener)

        renderUserVehicleFromPrefs(sp)

        if (jwt.isNullOrBlank() || userId.isNullOrBlank()) {
            openSignUp()
            return
        }

        viewLifecycleOwner.lifecycleScope.launch {
            if (!lastVin.isNullOrBlank() &&
                fetchAndPersistUserVin(sp, jwt, userId, lastVin)
            ) {
                return@launch
            }

            val list = tryGetUserVehicles(jwt, userId)
            if (list.isNotEmpty()) {
                val chosenVin = list.first().vin
                sp.edit().putString("last_vin", chosenVin).apply()
                fetchAndPersistUserVin(sp, jwt, userId, chosenVin)
            } else {
                openAddVehicle()
            }
        }
    }

    // ---------- UI helpers ----------

    private fun setupStatusChips(root: View) {
        val itemBt = root.findViewById<View>(R.id.itemBt)

        val itemEdit = root.findViewById<View>(R.id.itemEdit)

        itemBt.findViewById<ImageView>(R.id.imgIcon)
            .setImageResource(R.drawable.ic_bluetooth)

        itemEdit.findViewById<ImageView>(R.id.imgIcon)
            .setImageResource(R.drawable.ic_edit)

        itemEdit.findViewById<TextView>(R.id.tvLabel).text = "Edit Details"

        // initial state
        refreshConnectionStatus(root)
    }

    private fun renderUserVehicleFromPrefs(sp: SharedPreferences) {
        val json = sp.getString("last_vehicle_json", null) ?: return
        try {
            val obj = JSONObject(json)

            val name = obj.optString("name")
            val vin = obj.optString("vin")
            val model = obj.optString("model")
            val year = obj.optInt("year", 0)
            val image = obj.optString("image_url")

            // Header
            view?.findViewById<TextView>(R.id.tvUserName)?.text =
                if (name.isNullOrBlank()) "User" else name

            // Vehicle card
            view?.findViewById<TextView>(R.id.tvVehicleName)?.text =
                if (model.isNullOrBlank()) "My Vehicle" else model

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

            val img = view?.findViewById<ImageView>(R.id.imgScooter)
            if (!image.isNullOrBlank() && img != null) {
                val resName = image.substringBeforeLast('.')
                val resId = resources.getIdentifier(
                    resName,
                    "drawable",
                    requireContext().packageName
                )
                if (resId != 0) {
                    img.setImageResource(resId)
                } else {
                    // If you use remote URL, load via Glide/Picasso here
                }
            }
        } catch (_: Exception) {
            // ignore bad JSON
        }
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

                renderUserVehicleFromPrefs(sp)
                true
            } else false
        } else false
    } catch (_: HttpException) {
        false
    } catch (_: Exception) {
        false
    }

    private suspend fun tryGetUserVehicles(
        jwt: String?,
        userId: String?
    ): List<UserVehicleItem> = try {
        val resp = ApiClient.api.getUserVehicles("Bearer $jwt", userId)
        if (resp.isSuccessful) resp.body()?.response.orEmpty() else emptyList()
    } catch (_: Exception) {
        emptyList()
    }

    // ---------- Navigation to other top-level screens ----------

    private fun openSignUp() {
        parentFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, SignUpFragment())
            .addToBackStack(null)
            .commit()
    }

    private fun openAddVehicle() {
        if (!isAdded || view == null ||
            !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        ) return

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
        val appCtx = requireActivity().applicationContext
        val appSp = appCtx.getSharedPreferences("pairing_prefs", Context.MODE_PRIVATE)
        prefsListener?.let {
            appSp.unregisterOnSharedPreferenceChangeListener(it)
            prefsListener = null
        }
        _binding = null
        super.onDestroyView()
    }
}
