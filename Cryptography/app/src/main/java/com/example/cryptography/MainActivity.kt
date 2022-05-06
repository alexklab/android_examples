package com.example.cryptography

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security


class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Security.removeProvider("BC")
        // Confirm that positioning this provider at the end works for your needs!
        Security.addProvider(BouncyCastleProvider())


       // Util.testBcToBc()

        Util.test1()
    }
}