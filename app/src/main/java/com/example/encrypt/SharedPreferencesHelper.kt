package com.example.encrypt

import android.content.Context

class SharedPreferencesHelper {

    companion object {

        fun putData(context: Context, sharedName: String, key: String, data: String) {
            val shared = context.getSharedPreferences(sharedName, Context.MODE_PRIVATE)
            val editor = shared.edit()
            editor.putString(key, data)
            editor.apply()
        }

        fun getData(context: Context, sharedName: String, key: String): String? {
            val shared = context.getSharedPreferences(sharedName, Context.MODE_PRIVATE)
            return shared.getString(key, "")
        }

    }
}