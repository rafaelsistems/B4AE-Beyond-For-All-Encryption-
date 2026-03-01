package com.b4ae.app

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.b4ae.B4AE
import kotlinx.coroutines.*
import java.util.concurrent.Executors

/**
 * Enhanced B4AE Android Demo Application
 * 
 * Demonstrates full quantum-safe cryptography including:
 * - Post-quantum key exchange (Kyber-1024)
 * - Post-quantum signatures (Dilithium5)
 * - AES-256-GCM encryption
 * - Complete handshake protocol
 * - Session management
 */
class EnhancedMainActivity : AppCompatActivity() {
    
    companion object {
        private const val TAG = "B4AEEnhancedDemo"
    }
    
    private lateinit var statusText: TextView
    private lateinit var benchmarkText: TextView
    private lateinit var generateKeyButton: Button
    private lateinit var handshakeButton: Button
    private lateinit var encryptButton: Button
    private lateinit var benchmarkButton: Button
    
    private var b4aeClient: B4AE.B4AEClient? = null
    private var peerKeypair: B4AE.Keypair? = null
    private var sharedSecret: ByteArray? = null
    private var sessionEstablished = false
    
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val mainExecutor = Executors.newSingleThreadExecutor()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_enhanced_main)
        
        initializeViews()
        setupClickListeners()
        initializeB4AE()
    }
    
    private fun initializeViews() {
        statusText = findViewById(R.id.statusText)
        benchmarkText = findViewById(R.id.benchmarkText)
        generateKeyButton = findViewById(R.id.generateKeyButton)
        handshakeButton = findViewById(R.id.handshakeButton)
        encryptButton = findViewById(R.id.encryptButton)
        benchmarkButton = findViewById(R.id.benchmarkButton)
        
        updateUI()
    }
    
    private fun setupClickListeners() {
        generateKeyButton.setOnClickListener { performKeyGeneration() }
        handshakeButton.setOnClickListener { performHandshake() }
        encryptButton.setOnClickListener { performEncryptionDemo() }
        benchmarkButton.setOnClickListener { runBenchmarks() }
    }
    
    private fun initializeB4AE() {
        scope.launch {
            try {
                logInfo("Initializing B4AE Mobile SDK...")
                logInfo("Version: ${B4AE.getVersion()}")
                
                b4aeClient = B4AE.initialize(B4AE.SecurityProfile.HIGH)
                logInfo("B4AE client initialized successfully")
                
                val securityInfo = B4AE.getSecurityInfo(b4aeClient!!)
                logInfo("Security Info: $securityInfo")
                
                updateStatus("B4AE initialized successfully")
            } catch (e: Exception) {
                logError("Failed to initialize B4AE", e)
                updateStatus("Initialization failed: ${e.message}")
            }
        }
    }
    
    private fun performKeyGeneration() {
        scope.launch {
            try {
                updateStatus("Generating quantum-safe keypair...")
                
                val startTime = System.currentTimeMillis()
                val keypair = B4AE.generateKeypair(b4aeClient!!)
                val endTime = System.currentTimeMillis()
                
                peerKeypair = keypair
                
                logInfo("Keypair generated in ${endTime - startTime}ms")
                logInfo("Public key size: ${keypair.publicKey.size} bytes")
                logInfo("Secret key size: ${keypair.secretKey.size} bytes")
                
                updateStatus("Keypair generated (${endTime - startTime}ms)")
                updateUI()
                
                showToast("Quantum-safe keypair generated!")
            } catch (e: Exception) {
                logError("Key generation failed", e)
                updateStatus("Key generation failed: ${e.message}")
            }
        }
    }
    
    private fun performHandshake() {
        scope.launch {
            try {
                if (peerKeypair == null) {
                    updateStatus("Please generate keypair first")
                    return@launch
                }
                
                updateStatus("Performing quantum-safe handshake...")
                
                // Simulate peer
                val peerClient = B4AE.initialize(B4AE.SecurityProfile.HIGH)
                val peerKeypairLocal = B4AE.generateKeypair(peerClient)
                
                val startTime = System.currentTimeMillis()
                
                // Alice initiates handshake
                val aliceHandshake = B4AE.performHandshake(b4aeClient!!, "bob")
                
                // Bob responds (simulated)
                val bobResponse = B4AE.completeHandshake(peerClient, "alice", aliceHandshake)
                
                // Complete handshake
                val handshakeComplete = B4AE.completeHandshake(b4aeClient!!, "bob", aliceHandshake)
                
                val endTime = System.currentTimeMillis()
                
                sessionEstablished = handshakeComplete
                
                logInfo("Handshake completed in ${endTime - startTime}ms")
                logInfo("Session established: $sessionEstablished")
                
                updateStatus("Handshake completed (${endTime - startTime}ms)")
                updateUI()
                
                // Cleanup peer client
                peerClient.dispose()
                
                showToast("Quantum-safe handshake completed!")
            } catch (e: Exception) {
                logError("Handshake failed", e)
                updateStatus("Handshake failed: ${e.message}")
            }
        }
    }
    
    private fun performEncryptionDemo() {
        scope.launch {
            try {
                if (!sessionEstablished) {
                    updateStatus("Please complete handshake first")
                    return@launch
                }
                
                updateStatus("Performing quantum-safe encryption...")
                
                val testMessage = "Hello from quantum-safe Android! 🚀".toByteArray()
                
                val startTime = System.currentTimeMillis()
                
                // Encrypt message
                val encryptedMessages = B4AE.encryptMessage(b4aeClient!!, "bob", testMessage)
                
                // Decrypt message
                val decryptedMessage = B4AE.decryptMessage(b4aeClient!!, "bob", encryptedMessages)
                
                val endTime = System.currentTimeMillis()
                
                val decryptedText = String(decryptedMessage, Charsets.UTF_8)
                val success = testMessage.contentEquals(decryptedMessage)
                
                logInfo("Encryption completed in ${endTime - startTime}ms")
                logInfo("Original: ${String(testMessage, Charsets.UTF_8)}")
                logInfo("Decrypted: $decryptedText")
                logInfo("Success: $success")
                
                updateStatus("Encryption completed (${endTime - startTime}ms) - Success: $success")
                
                showToast(if (success) "Encryption successful!" else "Encryption failed!")
            } catch (e: Exception) {
                logError("Encryption failed", e)
                updateStatus("Encryption failed: ${e.message}")
            }
        }
    }
    
    private fun runBenchmarks() {
        scope.launch {
            try {
                updateStatus("Running performance benchmarks...")
                
                val results = StringBuilder()
                results.append("B4AE Performance Benchmarks\n")
                results.append("============================\n\n")
                
                // Key generation benchmark
                val keygenTimes = mutableListOf<Long>()
                for (i in 0..10) {
                    val start = System.currentTimeMillis()
                    val keypair = B4AE.generateKeypair(b4aeClient!!)
                    val end = System.currentTimeMillis()
                    keygenTimes.add(end - start)
                }
                val avgKeygen = keygenTimes.average()
                results.append("Key Generation: ${avgKeygen}ms average\n")
                
                // Handshake benchmark
                val handshakeTimes = mutableListOf<Long>()
                for (i in 0..5) {
                    val peerClient = B4AE.initialize(B4AE.SecurityProfile.HIGH)
                    
                    val start = System.currentTimeMillis()
                    val handshake = B4AE.performHandshake(b4aeClient!!, "peer_$i")
                    B4AE.completeHandshake(b4aeClient!!, "peer_$i", handshake)
                    val end = System.currentTimeMillis()
                    
                    handshakeTimes.add(end - start)
                    peerClient.dispose()
                }
                val avgHandshake = handshakeTimes.average()
                results.append("Handshake: ${avgHandshake}ms average\n")
                
                // Encryption benchmark
                val testData = ByteArray(1024) { it.toByte() }
                val encryptTimes = mutableListOf<Long>()
                
                for (i in 0..100) {
                    val start = System.currentTimeMillis()
                    val encrypted = B4AE.encryptMessage(b4aeClient!!, "bob", testData)
                    val end = System.currentTimeMillis()
                    encryptTimes.add(end - start)
                }
                val avgEncrypt = encryptTimes.average()
                results.append("Encryption (1KB): ${avgEncrypt}ms average\n")
                
                // Throughput calculation
                val totalTime = encryptTimes.sum()
                val throughput = (testData.size * encryptTimes.size * 1000.0) / totalTime
                results.append("Throughput: ${throughput}KB/s\n")
                
                // Memory usage (approximate)
                val runtime = Runtime.getRuntime()
                val usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
                results.append("Memory Usage: ${usedMemory}MB\n")
                
                updateBenchmarkText(results.toString())
                updateStatus("Benchmarks completed")
                
                logInfo("Benchmarks completed successfully")
            } catch (e: Exception) {
                logError("Benchmark failed", e)
                updateStatus("Benchmark failed: ${e.message}")
            }
        }
    }
    
    private fun updateUI() {
        runOnUiThread {
            generateKeyButton.isEnabled = b4aeClient != null
            handshakeButton.isEnabled = b4aeClient != null && peerKeypair != null
            encryptButton.isEnabled = b4aeClient != null && sessionEstablished
            benchmarkButton.isEnabled = b4aeClient != null
        }
    }
    
    private fun updateStatus(message: String) {
        runOnUiThread {
            statusText.text = message
        }
        logInfo("Status: $message")
    }
    
    private fun updateBenchmarkText(text: String) {
        runOnUiThread {
            benchmarkText.text = text
        }
    }
    
    private fun showToast(message: String) {
        runOnUiThread {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun logInfo(message: String) {
        Log.i(TAG, message)
    }
    
    private fun logError(message: String, throwable: Throwable? = null) {
        Log.e(TAG, message, throwable)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        // Cleanup resources
        scope.cancel()
        b4aeClient?.dispose()
        
        logInfo("Activity destroyed, resources cleaned up")
    }
}