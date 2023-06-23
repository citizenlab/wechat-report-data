/** 
 * This Frida script hooks all functions belonging to particular classes.
 * It prints all parameters and return objects from these classes.
 *
 * Code ported from: https://codeshare.frida.re/@qiaoruntao/hook-douyin/
 *
 * These class definitions are from 8023 / 2160 APK:
 * https://dldir1.qq.com/weixin/android/weixin8023android2160_arm64_1.apk
 */
var Color = {
    RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
    Light: {
        Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
    }
};

/**
 *
 * @param input. 
 *      If an object is passed it will print as json 
 * @param kwargs  options map {
 *     -l level: string;   log/warn/error
 *     -i indent: boolean;     print JSON prettify
 *     -c color: @see ColorMap
 * }
 */
var LOG = function (input, kwargs) {
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log', colorPrefix = '\x1b[3', colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
};

var printBacktrace = function () {
    Java.perform(function() {
        var android_util_Log = Java.use('android.util.Log'), java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        LOG(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
    });
};

function obj2hex(obj) {
	var hex1 = '';
	for (var k = 0, l = obj.length; k < l; k++) {
		var intvalue = parseInt(obj[k]);
		intvalue &= 0xff;
		if ( intvalue < 0 || intvalue > 255 ) console.log('EEEEEEEE unexpected intvalue!');
		hex1 += ('0'+intvalue.toString(16)).substr(-2) + " ";
	}
	return hex1;
}

function traceClass(targetClass, logargs=true, displayClassName) {
    var hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        console.error("trace class failed", e);
        return;
    }

    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();

    var parsedMethods = [];
    methods.forEach(function (method) {
        var methodStr = method.toString();
        var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
         parsedMethods.push(methodReplace);
    });

    uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
        traceMethod(targetClass + '.' + targetMethod, logargs, displayClassName);
    });
}

function traceMethod(targetClassMethod, logargs=true, displayClassName) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

	var displayClassMethodName = '';
	if (typeof displayClassName === 'string' || displayClassName instanceof String) {
		displayClassMethodName = displayClassName + '.' + targetMethod;
	} else {
		displayClassMethodName = targetClass + '.' + targetMethod;
	}

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
			var logstart = { 'MAIN ENTER': displayClassMethodName };
            LOG(logstart, { c: Color.Yellow });
            var log = { 'MAIN LEAVE': displayClassMethodName, args: [] };

			if ( logargs ) {
				for (var j = 0; j < arguments.length; j++) {
					var arg = arguments[j];

					if (arguments[j] && arguments[j].toString() === '[object Object]') {
						// quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
						var s = [];
						for (var k = 0, l = arguments[j].length; k < l; k++) {
							s.push(arguments[j][k]);
						}
						arg = s.join('');
					} else if ( arguments[j] && typeof arguments[j] === 'object' ) {//frida returns Java byte[] as JS object
						arg = obj2hex(arguments[j]);
					}
					if ( arg && arg != arg.toString() ) {
						log.args.push({ i: j, o: arg, s: arg.toString()});
					} else {
						log.args.push({ i: j, o: arg});
					}
				}
			}

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
				if ( retval && typeof(retval) == "object" && retval.length > 100 ) {
					log.returnnote = "Array>100";
					log.returnsize = retval.length;
					log.returns = { str: "[Array>100]"+obj2hex(retval).slice(0,300)};
				} else if ( retval && typeof retval === 'object' ) {//frida returns Java byte[] as JS object
					log.returns = { val: obj2hex(retval) };
				} else {
					log.returns = { val: retval, str: retval ? retval.toString() : null };
				}
            } catch (e) {
                console.error(e);
            }
            LOG(log, { c: Color.Yellow });
            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}


var Main = function() {
    Java.perform(function () { // avoid java.lang.ClassNotFoundException
        // Classes that we're hooking.
        [
 			'com.tencent.mm.jni.utils.UtilsJni',
 			'com.tencent.mm.protocal.MMProtocalJni',
 			{obfname: 'com.tencent.mm.an.w', display: "RemoteReq"},
 			{obfname: 'com.tencent.mm.an.x', display: "RemoteReqResp"},
        ].forEach(function (aclass) { 
			var target_class = '';
			var displayClassName;
			if (typeof aclass === 'string' || aclass instanceof String) {
				target_class = aclass;
			} else {
				target_class = aclass.obfname;
				displayClassName = aclass.display;
			}

			traceClass(target_class, true, displayClassName);
		});
    });
};

Java.perform(Main);
