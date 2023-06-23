# WeChat dynamic analysis setup
This will walk you through setup for WeChat mobile app on Android (for either an emulated or rooted device), and setup for both Wireshark and Frida instrumentation for analysis.
1. ADB setup
For emulation:
Android Studio, create new image of Pixel 5 API 32 with at least 5GB internal storage, optionally more in SD card if you’d like.
brew install android-platform-tools
If using real device, make sure device is rooted, connect using USB.
`adb devices` should list either the emulated or the rooted device.
Run `adb root`.
2. WeChat setup
Download Wechat APK compiled form arm64-v8a / armeabi-v7a (assuming wechat.apk) from the official version list here:
https://weixin.qq.com/cgi-bin/readtemplate?lang=zh_CN&t=weixin_faq_list
We are looking at version 8023.
```
apk install wechat.apk
```

3. Network inspection setup
tcpdump should already be installed on the Android device if the version is recent. Similarly, on the host device, if android-platform-tools is installed then androiddump should be installed as well.
On host computer, ensure “tshark -D” lists an android interface. For an emulator this should be something like “android-tcpdump-any-emulator-5554”. You should then be able to sniff all traffic on the Android device with Wireshark by selecting this interface.
4. Frida setup
https://frida.re/docs/android/
Download frida-server from https://github.com/frida/frida/releases for the correct architecture of your emulated or real device (in my case, android-arm64)
```
pip3 install frida-tools
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```
5. Putting it all together
To test to make sure it is working, on host, type:
```
frida-trace -U -i “Java_com_tencent_mm_protocal_*” WeChat
```

Then on the WeChat application, change the application language (this should be possible even without logging in). This will consistently generate a single MMTLS request. Frida should see a single call to 
```
Java_com_tencent_mm_protocal_MMProtocalJni_packHybridEcdh()
Java_com_tencent_mm_protocal_MMProtocalJni_unpack()
```
per MMTLS request. You can verify that a single MMTLS request has occurred via Wireshark.
Mobile static analysis
For static analysis we are mostly using https://github.com/skylot/jadx and the associated GUI. 

## Running these scripts

These scripts should work by running:
```
frida -U -f com.tencent.mm -l [frida-script].js
```

