# SafetyNetSampleApp
SafetyNet consists of four major api:
1. Attestation API
2. Safe Browsing API
3. reCAPTCHA API
4. Verify Apps API

Google offers many other options like application sandboxing, encryption, app-based permissions and so on to secularize apps but none of them are considered as an all-inclusive solution. For instance, a sandbox can be easily broken out through device rooting or using intelligent malicious codes. 

Using SafetyNet services it’s possible to build secure apps that refuse to run on such tampered device environments.


SafetyNet Attestation API – Checks whether the gadget the application is attempting to run on is tampered or potentially compromised. It compares the device’s profile with that of Google certified devices and verifies if the device or the software running on it is Android compatible.


SafetyNet Safe Browsing API – Checks whether a URL used within an application is marked by Google as malicious. If the API is implemented with an application, Google scans the web pages running inside the application and compare them with the constantly updated blacklist of threatful websites maintained by Google. If any malware or harmful codes are found within the page, a warning page will be added by SafetyNet and the URL will be classified as a known threat.


SafetyNet reCAPTCHA API – Checks for spam or abusive actions by detecting whether it’s an actual person who’s interacting with the application. It uses information from an advanced risk analysis engine to protect the application from malicious traffic. A captcha will be enforced if the user is suspected to be a bot instead of a real human. The application continues working only if a human solves the captcha.


SafetyNet Verify Apps API – Checks whether the user has enabled the Verify apps feature on the device and ensures that no known potentially harmful application is running on the Android gadget. The service coordinate with the Verify apps feature to make sure that the app’s data is protected as no other apps on the device on which the app is currently running can perform any malicious actions. With this API you can further confirm that the user’s device is having Verify apps feature enabled on it and if not, you can encourage them to use it.

More on SafetyNet Attestation API:
The API determines the integrity issues on the device and compares the corresponding device profile against the whitelisted device models having Google-approved device profiles. The software backed and hardware-based device profile can be considered compatible only if it matches up with any of the approved profiles in the reference list. A device is considered as approved by Google if it passes the Android Compatibility Test Suite (CTS). Thus, by comparing the device profile against the CTS standards, the API verifies the following:

1. Whether the device is rooted or not.
2. Whether the device is monitored.
3. Whether the bootloader has been unlocked.
4. Whether the device has recognized hardware parameters.
5. Whether the software is Android compatible.
6. Whether the device is free form malicious apps.

