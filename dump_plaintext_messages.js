/**
 * This Frida script hooks functions that are responsible for encrypting and decrypting
 * network plaintext messages. In particular, we hook:
 *
 * MMProtocalJni.unpack
 * UtilsJni.HybridEcdhEncrypt
 *
 * Native functions in libMMProtocalJni.so:
 *  * AesEncrypt at address 0x0013d108
 *
 * the calculated function offsets and class definitions are from 8.0.23 / 2160 APK:
 * https://dldir1.qq.com/weixin/android/weixin8023android2160_arm64_1.apk
 */

const GHIDRA_BASE = 0x00100000;
const MODULE_NAME = "libMMProtocalJni.so";

function timelog(message) {
    console.log("[" + new Date().toISOString() + "] "
        + message);
}

function errorlog(message) {
    timelog("[ERROR] " + message);
}

function inspectAES(args) {
    timelog("----AESEncrypt----")
    timelog("----REQUEST PLAINTEXT----");
    var datalen = parseInt(String(args[5]), 16);
    console.log(hexdump(args[4], {length: datalen, header: false, ansi: false}));
    timelog("----END REQUEST PLAINTEXT----");
}

// offsets from 8023 / 2160 version. link:
// https://dldir1.qq.com/weixin/android/weixin8023android2160_arm64_1.apk
var target_funcs = [
     {addr: 0x0013d108, name: "AES", onEnterFn: inspectAES},
];

function hookFuncs() {
    var module = Process.findModuleByName(MODULE_NAME);
    if (module == null) {
        errorlog("module was null");
        return;
    }
    timelog("Module found: " + MODULE_NAME);
    var moduleBaseAddress = Module.findBaseAddress(MODULE_NAME);

    target_funcs.map( ({name, addr, onEnterFn}) => {
        const realAddr = moduleBaseAddress.add(addr - GHIDRA_BASE);
        if (onEnterFn == null) {
            onEnterFn = (args) => timelog('Called ' + name);
        }
        Interceptor.attach(realAddr, {
            onEnter: onEnterFn,
        });
        timelog('Hooked '+name+ " at " + realAddr);
    });
}

function delay(time) {
    return new Promise(resolve => setTimeout(resolve, time));
}

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function (args) {
        var arg = args[0].readUtf8String();
        this.foun = null;
        var modules = [MODULE_NAME];
        for (var i = 0; i < modules.length; i++) {
            if (arg.includes(modules[i])) {
                this.found = modules[i];
            }
        }
        if (arg.includes(MODULE_NAME)) {
            setTimeout(hookFuncs, 100);
        }
    },
    onLeave: function(retval) {
        if (this.found != null) {
            delay(10).then(() => bindAllModuleFunctions(this.found));
        }
    }
});


function bindFunction(module, name) {
    Interceptor.attach(Module.findExportByName(module, name), {
        onEnter: function(args) {
            timelog(module+": " + name + " called");
        },
    });
}

function bindAllModuleFunctions(module) {
    var module = Process.findModuleByName(module);
    if (module != null) {
        timelog(module.name+" library loaded");
        var exports = module.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
            if (!exports[i].name.includes("Log") && !exports[i].includes("logger")) {
                bindFunction(module.name, exports[i].name);
            }
        }
    } else {
        timelog(module+" library not loaded");
    }
}


Java.perform(function(){
    var UtilsJni = Java.use("com.tencent.mm.jni.utils.UtilsJni");
    var toHexString = function(byteArray) {
      return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join('');
    };

    UtilsJni.HybridEcdhEncrypt.overload(
        'long', '[B'
    ).implementation = function(crypto_engine_id, plaintext) {
        timelog("----HybridEcdhEncrypt----");
        timelog("----REQUEST PLAINTEXT----");
        console.log(toHexString(plaintext));
        timelog("----END REQUEST PLAINTEXT----");
        const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
        const StringClass = Java.use('java.lang.String');
        const hexChars = HexClass.encodeHex(plaintext);
        var ciphertext = this.HybridEcdhEncrypt(crypto_engine_id, plaintext);
        return ciphertext;
    };

    var MMProtocalJni = Java.use("com.tencent.mm.protocal.MMProtocalJni");
    var PByteArray = Java.use('com.tencent.mm.pointers.PByteArray');

    MMProtocalJni.unpack.overload(
        'com.tencent.mm.pointers.PByteArray',
        '[B',
        '[B',
        'com.tencent.mm.pointers.PByteArray',
        'com.tencent.mm.pointers.PInt',
        'com.tencent.mm.pointers.PInt',
        'com.tencent.mm.pointers.PInt',
        'com.tencent.mm.pointers.PInt',
    ).implementation = function(p1, p2, p3, p4, p5, p6, p7, p8) {
        var result = this.unpack(p1, p2, p3, p4, p5, p6, p7, p8);
        var plaintext = p1.value.value;
        timelog("----unpack----");
        timelog("----RESPONSE PLAINTEXT----");
        console.log(toHexString(plaintext));
        timelog("----END RESPONSE PLAINTEXT----");
        return result;
    };
})
