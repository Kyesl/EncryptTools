package com.example.encrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.KeyEvent
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import java.lang.Exception

class MainActivity : AppCompatActivity() {

    companion object {
        const val AES_KEY = "1234567890abcdef1234567890abcdef"
    }

    private lateinit var et_input: EditText
    private lateinit var tv_encrypt: TextView
    private lateinit var tv_decrypt: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        et_input = findViewById(R.id.et_input)
        tv_encrypt = findViewById(R.id.tv_encrypt)
        tv_decrypt = findViewById(R.id.tv_decrypt)

        et_input.setOnEditorActionListener { _, actionId, _ ->
            try {
                if (actionId == EditorInfo.IME_ACTION_DONE) {
//                var encodeData = EncryptManger.base64Encode(et_input.text.toString())
//                tv_encrypt.text = encodeData
//                var decodeData = EncryptManger.base64Decode(encodeData)
//                tv_decrypt.text = decodeData

//                var encodeData = EncryptManger.instance.md5Encode(et_input.text.toString())

                    var encodeData =
                        EncryptManger.instance.aesEncode(this, et_input.text.toString())
                    tv_encrypt.text = encodeData

                    var decodeData = EncryptManger.instance.aesDecode(this, encodeData)
                    tv_decrypt.text = decodeData
                }
            }catch (e: Exception) {
                e.stackTrace
                println(e.toString())
            }

            false
        }


    }



}
