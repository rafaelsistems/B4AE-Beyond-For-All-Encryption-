package com.b4ae.app

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.b4ae.B4AE

class MainActivity : AppCompatActivity() {

    private var key: ByteArray? = null
    private var encrypted: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        val status = TextView(this).apply {
            text = "B4AE Platform SDK Demo - AES-256-GCM"
            textSize = 18f
            setPadding(0, 0, 0, 24)
        }
        layout.addView(status)

        val result = TextView(this).apply {
            text = ""
            textSize = 14f
            setPadding(0, 16, 0, 16)
        }
        layout.addView(result)

        fun updateResult(msg: String) {
            result.text = msg
        }

        layout.addView(Button(this).apply {
            text = "1. Generate Key"
            setOnClickListener {
                try {
                    key = B4AE.generateKey()
                    updateResult("Key generated: ${key!!.size} bytes")
                    Toast.makeText(this@MainActivity, "Key generated", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    updateResult("Error: ${e.message}")
                }
            }
        })

        layout.addView(Button(this).apply {
            text = "2. Encrypt 'Hello B4AE!'"
            setOnClickListener {
                try {
                    val k = key ?: run {
                        updateResult("Generate key first")
                        return@setOnClickListener
                    }
                    encrypted = B4AE.encrypt(k, "Hello B4AE!".toByteArray())
                    updateResult("Encrypted: ${encrypted!!.size} bytes")
                    Toast.makeText(this@MainActivity, "Encrypted", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    updateResult("Error: ${e.message}")
                }
            }
        })

        layout.addView(Button(this).apply {
            text = "3. Decrypt"
            setOnClickListener {
                try {
                    val k = key ?: run {
                        updateResult("Generate key first")
                        return@setOnClickListener
                    }
                    val enc = encrypted ?: run {
                        updateResult("Encrypt first")
                        return@setOnClickListener
                    }
                    val dec = B4AE.decrypt(k, enc)
                    updateResult("Decrypted: ${String(dec)}")
                    Toast.makeText(this@MainActivity, "Decrypted: ${String(dec)}", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    updateResult("Error: ${e.message}")
                }
            }
        })

        setContentView(layout)
    }
}
