package ir.behnoudsh.safetynetsampleapp

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.text.Html
import android.text.Spanned
import android.util.Log
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.safetynet.SafeBrowsingThreat
import com.google.android.gms.safetynet.SafetyNet
import com.google.android.gms.tasks.Tasks
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom
import java.util.*
import android.util.Base64
import android.widget.TextView
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    companion object {
        private val TAG = MainActivity::class.simpleName
    }

    private val mRandom: Random = SecureRandom()
    private lateinit var textOutput: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        textOutput = findViewById(R.id.sample_output)
        checkForSafetyNetAssest()
    }

    private fun checkForSafetyNetAssest() {
        if (GoogleApiAvailability.getInstance()
                .isGooglePlayServicesAvailable(this, 13000000) ==
            ConnectionResult.SUCCESS
        ) {
            val nonceData = "Safety Net Sample: " + System.currentTimeMillis()
            val nonce = getRequestNonce(nonceData)
            SafetyNet.getClient(this).attest(nonce, "AIzaSyDuiUjDCpG1QJgEeSepecgHs8Kk4qf1NqQ")
                .addOnSuccessListener(this) {
                    // Indicates communication with the service was successful.
                    // Use response.getJwsResult() to get the result data.
                    Log.d(TAG, "Success! SafetyNet result:\n" + it.jwsResult + "\n");
                    process(it.jwsResult)
                }
                .addOnFailureListener(this) { e ->
                    // An error occurred while communicating with the service.
                    if (e is ApiException) {
                        // An error with the Google Play services API contains some
                        // additional details.
                        val apiException = e as ApiException

                        // You can retrieve the status code using the
                        // apiException.statusCode property.
                    } else {
                        // A different, unknown type of error occurred.
                        Log.d(TAG, "Error: " + e.message)
                    }
                }

        } else {
            // Prompt user to update Google Play Services.
        }
    }

    /**
     * Generates a 16-byte nonce with additional data.
     * The nonce should also include additional information, such as a user id or any other details
     * you wish to bind to this attestation. Here you can provide a String that is included in the
     * nonce after 24 random bytes. During verification, extract this data again and check it
     * against the request that was made with this nonce.
     */
    private fun getRequestNonce(data: String): ByteArray? {
        val byteStream = ByteArrayOutputStream()
        val bytes = ByteArray(24)
        mRandom.nextBytes(bytes)
        try {
            byteStream.write(bytes)
            byteStream.write(data.toByteArray())
        } catch (e: IOException) {
            return null
        }
        return byteStream.toByteArray()
    }


    /**
     * Extracts the data part from a JWS signature.
     */
    private fun extractJwsData(jws: String?): ByteArray? {
        // The format of a JWS is:
        // <Base64url encoded header>.<Base64url encoded JSON data>.<Base64url encoded signature>
        // Split the JWS into the 3 parts and return the JSON data part.
        val parts = jws?.split("[.]".toRegex())?.dropLastWhile { it.isEmpty() }?.toTypedArray()
        if (parts?.size != 3) {
            System.err.println(
                "Failure: Illegal JWS signature format. The JWS consists of "
                        + parts?.size + " parts instead of 3."
            )
            return null
        }
        return Base64.decode(parts[1], Base64.DEFAULT)
    }

    private fun process(signedAttestationStatement: String?) {
        val stmt = extractJwsData(signedAttestationStatement)
        if (stmt == null) {
            System.err.println("Failure: Failed to parse and verify the attestation statement.")
            return
        }
        val safetyNetResult = JSONObject(String(stmt))
        // Nonce that was submitted as part of this request.
        val nonce = safetyNetResult.opt("nonce")
        val timestampMs = safetyNetResult.opt("timestampMs")
        val apkPackageName = safetyNetResult.opt("apkPackageName")
        val apkDigestSha256 = safetyNetResult.opt("apkDigestSha256")
        val apkCertificateDigestSha256 = safetyNetResult.opt("apkCertificateDigestSha256")
        val basicIntegrity = safetyNetResult.opt("basicIntegrity")
        val ctsProfileMatch = safetyNetResult.opt("ctsProfileMatch")

        val format = String.format(
//                "<p><strong>nonce</strong> = %s</p>\n" +
//                "<p><strong>TimeStamp</strong> = %s</p>\n" +
            "<strong>apkPackageName</strong>&nbsp;= %s<br>" +
//                "<p><strong>apkDigestSha256</strong> = %s</p>\n" +
//                "<p><strong>apkCertificateDigestSha256</strong> = %s</p>\n" +
                    "<strong>CTS&nbsp;approved</strong> = %s<br>" +
                    "<strong>Basic Integrity Approved</strong> = %s",
//                nonce ?: "none",
//                timestampMs ?: "none",
            apkPackageName ?: "none",
//                apkDigestSha256 ?: "none"
//                , apkCertificateDigestSha256 ?: "none",
            basicIntegrity ?: "none",
            ctsProfileMatch ?: "none"
        )

        textOutput.text = fromHtml(format)
    }

    private fun fromHtml(html: String): Spanned {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Html.fromHtml(html, Html.FROM_HTML_MODE_LEGACY)
        } else {
            Html.fromHtml(html)
        }
    }
}