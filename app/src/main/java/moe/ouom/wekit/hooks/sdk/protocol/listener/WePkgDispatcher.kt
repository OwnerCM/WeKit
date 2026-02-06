package moe.ouom.wekit.hooks.sdk.protocol.listener

import de.robv.android.xposed.XposedHelpers
import moe.ouom.wekit.core.dsl.dexClass
import moe.ouom.wekit.core.model.ApiHookItem
import moe.ouom.wekit.dexkit.intf.IDexFind
import moe.ouom.wekit.hooks.core.annotation.HookItem
import moe.ouom.wekit.hooks.sdk.protocol.WePkgHelper
import moe.ouom.wekit.hooks.sdk.protocol.WePkgManager
import moe.ouom.wekit.util.common.SyncUtils
import moe.ouom.wekit.util.log.WeLogger
import org.luckypray.dexkit.DexKitBridge

@HookItem(path = "protocol/wepkg_dispatcher", desc = "WePkg 请求/响应数据包拦截与篡改")
class WePkgDispatcher : ApiHookItem(), IDexFind {
    private val dexClsOnGYNetEnd by dexClass()

    override fun entry(classLoader: ClassLoader) {
        SyncUtils.postDelayed(3000) {
            val netSceneBaseClass = WePkgHelper.INSTANCE?.dexClsNetSceneBase?.clazz
            val callbackInterface = dexClsOnGYNetEnd.clazz

            if (netSceneBaseClass == null) {
                WeLogger.e("PkgDispatcher", "无法找到 NetSceneBase 类，跳过 WePkg 拦截器注入")
                return@postDelayed
            }

            hookBefore(netSceneBaseClass, "dispatch") { param ->
                val v0Var = param.args[1] ?: return@hookBefore
                val originalCallback = param.args[2] ?: return@hookBefore

                val uri = XposedHelpers.callMethod(v0Var, "getUri") as String
                val cgiId = XposedHelpers.callMethod(v0Var, "getType") as Int
                try {
                    val reqWrapper = XposedHelpers.callMethod(v0Var, "getReqObj")
                    val reqPbObj = XposedHelpers.getObjectField(reqWrapper, "a") // m.a
                    val reqBytes = XposedHelpers.callMethod(reqPbObj, "toByteArray") as ByteArray

                    WePkgManager.handleRequestTamper(uri, cgiId, reqBytes)?.let { tampered ->
                        XposedHelpers.callMethod(reqPbObj, "parseFrom", tampered)
                        WeLogger.i("PkgDispatcher", "Request Tampered: $uri")
                    }
                } catch (_: Throwable) {  }

                if (java.lang.reflect.Proxy.isProxyClass(originalCallback.javaClass)) return@hookBefore

                param.args[2] = java.lang.reflect.Proxy.newProxyInstance(
                    classLoader,
                    arrayOf(callbackInterface)
                ) { _, method, args ->
                    when (method.name) {
                        "hashCode" -> return@newProxyInstance originalCallback.hashCode()
                        "toString" -> return@newProxyInstance originalCallback.toString()
                        "equals" -> return@newProxyInstance originalCallback.equals(args?.get(0))
                        "onGYNetEnd" -> {
                            try {
                                val respV0 = args!![4] ?: v0Var
                                val respWrapper = XposedHelpers.getObjectField(respV0, "b") // n
                                val respPbObj = XposedHelpers.getObjectField(respWrapper, "a") // PB 实例
                                val originalRespBytes = XposedHelpers.callMethod(respPbObj, "toByteArray") as ByteArray

                                WePkgManager.handleResponseTamper(uri, cgiId, originalRespBytes)?.let { tampered ->
                                    XposedHelpers.callMethod(respPbObj, "parseFrom", tampered)
                                    WeLogger.i("PkgDispatcher", "Response Tampered (Memory): $uri")
                                }
                            } catch (t: Throwable) {
                                WeLogger.e("PkgDispatcher", "Tamper inner logic fail", t)
                            }
                        }
                    }

                    return@newProxyInstance method.invoke(originalCallback, *(args ?: emptyArray()))
                }
            }
        }
    }

    override fun dexFind(dexKit: DexKitBridge): Map<String, String> {
        val descriptors = mutableMapOf<String, String>()

        dexClsOnGYNetEnd.find(dexKit, descriptors,true) {
            searchPackages("com.tencent.mm.network")
            matcher {
                methodCount(1)
                methods {
                    add {
                        name = "onGYNetEnd"
                        paramCount = 6
                    }
                }
            }
        }

        return descriptors
    }
}