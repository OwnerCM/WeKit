package moe.ouom.wekit.hooks.sdk.api

import android.annotation.SuppressLint
import android.content.Context
import de.robv.android.xposed.XposedHelpers
import moe.ouom.wekit.config.RuntimeConfig
import moe.ouom.wekit.core.dsl.dexClass
import moe.ouom.wekit.core.dsl.dexMethod
import moe.ouom.wekit.core.model.ApiHookItem
import moe.ouom.wekit.dexkit.intf.IDexFind
import moe.ouom.wekit.hooks.core.annotation.HookItem
import moe.ouom.wekit.util.common.SyncUtils
import moe.ouom.wekit.util.log.WeLogger
import org.luckypray.dexkit.DexKitBridge
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * 微信消息发送 API
 * 基于: WeChat 8.0.68
 * 适配版本：WeChat <待补充> ~ 8.0.68
 */
@SuppressLint("DiscouragedApi")
@HookItem(path = "API/消息发送服务", desc = "提供文本、图片、文件消息发送能力")
class WeMessageApi : ApiHookItem(), IDexFind {

    // 基础消息类
    private val dexClassNetSceneSendMsg by dexClass()
    private val dexClassNetSceneQueue by dexClass()
    private val dexClassNetSceneBase by dexClass()
    private val dexClassNetSceneObserverOwner by dexClass()
    private val dexMethodGetSendMsgObject by dexMethod()
    private val dexMethodPostToQueue by dexMethod()
    private val dexMethodShareFile by dexMethod()

    // 图片发送核心类
    private val dexClassMvvmBase by dexClass()
    private val dexClassImageSender by dexClass()      // 发送逻辑核心
    private val dexClassImageTask by dexClass()        // 任务数据模型
    private val dexMethodImageSendEntry by dexMethod() // 静态入口方法
    private val dexClassServiceManager by dexClass() // x15.n0
    private val dexClassConfigLogic by dexClass()    // xv0.z1
    private val dexClassImageServiceImpl by dexClass()

    // 运行时缓存
    private var netSceneSendMsgClass: Class<*>? = null
    private var getSendMsgObjectMethod: Method? = null
    private var postToQueueMethod: Method? = null
    private var shareFileMethod: Method? = null
    private var getServiceMethod: Method? = null
    private var getSelfWxidMethod: Method? = null

    // 保存宿主 ClassLoader
    private var appClassLoader: ClassLoader? = null

    // 图片发送运行时对象
    private var p6Method: Method? = null
    private var imageMetadataMapField: Field? = null
    private var imageServiceApiClass: Class<*>? = null
    private var sendImageMethod: Method? = null

    // 文件发送运行时对象
    private var wxFileObjectClass: Class<*>? = null
    private var wxMediaMessageClass: Class<*>? = null

    // Unsafe 实例
    private var unsafeInstance: Any? = null
    private var allocateInstanceMethod: Method? = null

    // 反射获取构造函数缓存
    private var taskConstructor: java.lang.reflect.Constructor<*>? = null
    private var crossParamsClass: Class<*>? = null // d40.i0
    private var crossParamsConstructor: java.lang.reflect.Constructor<*>? = null

    companion object {
        private const val TAG = "WeMessageApi"
        private const val KEY_MAP_FIELD = "dexFieldImageMetadataMap"

        @SuppressLint("StaticFieldLeak")
        var INSTANCE: WeMessageApi? = null
    }

    override fun dexFind(dexKit: DexKitBridge): Map<String, String> {
        val descriptors = mutableMapOf<String, String>()

        try {
            WeLogger.i(TAG, ">>>> 开始查找消息发送 API (Process: ${SyncUtils.getProcessName()}) <<<<")

            dexClassNetSceneObserverOwner.find(dexKit, descriptors = descriptors) {
                matcher {
                    methods {
                        add {
                            paramCount = 4
                            usingStrings("MicroMsg.Mvvm.NetSceneObserverOwner")
                        }
                    }
                }
            }
            dexClassNetSceneSendMsg.find(dexKit, descriptors = descriptors) {
                matcher {
                    methods {
                        add {
                            paramCount = 1
                            usingStrings("MicroMsg.NetSceneSendMsg", "markMsgFailed for id:%d")
                        }
                    }
                }
            }
            dexClassNetSceneQueue.find(dexKit, descriptors = descriptors) {
                searchPackages("com.tencent.mm.modelbase")
                matcher {
                    methods {
                        add {
                            paramCount = 2
                            usingStrings("worker thread has not been se", "MicroMsg.NetSceneQueue")
                        }
                    }
                }
            }
            dexClassNetSceneBase.find(dexKit, descriptors = descriptors) {
                matcher {
                    methods {
                        add {
                            paramCount = 3
                            usingStrings("scene security verification not passed, type=")
                        }
                    }
                }
            }
            dexMethodGetSendMsgObject.find(dexKit, true, descriptors = descriptors) {
                matcher {
                    paramCount = 0
                    returnType = dexClassNetSceneObserverOwner.getDescriptorString() ?: ""
                }
            }
            dexMethodPostToQueue.find(dexKit, descriptors = descriptors) {
                searchPackages("com.tencent.mm.modelbase")
                matcher {
                    declaredClass = dexClassNetSceneQueue.getDescriptorString() ?: ""
                    paramTypes(dexClassNetSceneBase.getDescriptorString() ?: "")
                    returnType = "boolean"
                    usingNumbers(0)
                }
            }
            dexMethodShareFile.find(dexKit, descriptors = descriptors) {
                matcher { paramTypes("com.tencent.mm.opensdk.modelmsg.WXMediaMessage", "java.lang.String", "java.lang.String", "java.lang.String", "int", "java.lang.String") }
            }

            // 图片发送级联查找 //

            // 定位发送逻辑类 (x40.r)
            dexClassImageSender.find(dexKit, descriptors = descriptors) {
                matcher { usingStrings("MicroMsg.ImgUpload.MsgImgSyncSendFSC", "/cgi-bin/micromsg-bin/uploadmsgimg") }
            }

            val senderDesc = descriptors[dexClassImageSender.key]
            if (senderDesc != null) {
                // 级联查找入口方法 (p6)
                val sendMethodData = dexKit.findMethod {
                    matcher {
                        declaredClass = senderDesc
                        modifiers = Modifier.PUBLIC or Modifier.STATIC or Modifier.FINAL
                        paramCount = 4
                        paramTypes(senderDesc, null, null, null)
                    }
                }.singleOrNull()

                if (sendMethodData != null) {
                    descriptors[dexMethodImageSendEntry.key] = sendMethodData.descriptor

                    // 级联定位任务类 (k40.g)
                    // sendMethodData.paramTypes[1] 返回的是 Java 类名字符串
                    val taskClassName = sendMethodData.paramTypes[1]
                    descriptors[dexClassImageTask.key] = taskClassName.name

                    // 定位 Map 字段
                    // 在 DexKit 内部搜索时需要 JNI 格式的描述符 (L...;)
                    val taskDescriptorForSearch = "L" + taskClassName.name.replace(".", "/") + ";"
                    val mapFieldData = dexKit.findField {
                        matcher {
                            declaredClass = taskDescriptorForSearch
                            type = "java.util.Map"
                        }
                    }.singleOrNull()

                    if (mapFieldData != null) {
                        descriptors["${javaClass.simpleName}:$KEY_MAP_FIELD"] = mapFieldData.descriptor
                    }
                } else {
                    WeLogger.e(TAG, "查找失败: 未在 ImageSender 中找到静态入口 p6")
                }

                // 先定位 Mvvm 基类 (ki0.o)
                // 特征：包含日志字符串 "MicroMsg.Mvvm.MvvmPlugin"
                dexClassMvvmBase.find(dexKit, descriptors) {
                    matcher { usingStrings("MicroMsg.Mvvm.MvvmPlugin", "onAccountInitialized start") }
                }

                // 获取探测到的基类描述符，如 "Lki0/o;"
                val mvvmBaseDesc = descriptors[dexClassMvvmBase.key]

                // 定位图片服务实现类 (o40.q)
                // 逻辑：必须包含特定日志，且必须继承自刚才找到的基类
                if (mvvmBaseDesc != null) {
                    dexClassImageServiceImpl.find(dexKit, descriptors) {
                        matcher {
                            usingStrings("MicroMsg.ImgUpload.MsgImgFeatureService")
                            superClass(mvvmBaseDesc) // 动态引用，不再硬编码
                        }
                    }
                }

                // 定位其他辅助类
                dexClassServiceManager.find(dexKit, descriptors) {
                    matcher { usingStrings("MicroMsg.ServiceManager", "calling getService(...)") }
                }

                dexClassConfigLogic.find(dexKit, descriptors) {
                    matcher { usingStrings("MicroMsg.ConfigStorageLogic", "get userinfo fail") }
                }

                dexClassImageTask.find(dexKit, descriptors) {
                    matcher { usingStrings("msg_raw_img_send") }
                }
            }

            WeLogger.i(TAG, "DexKit 查找结束，共找到 ${descriptors.size} 项")
        } catch (e: Exception) {
            WeLogger.e(TAG, "查找过程崩溃", e)
            throw e
        }
        return descriptors
    }

    override fun entry(classLoader: ClassLoader) {
        try {
            INSTANCE = this
            appClassLoader = classLoader

            WeLogger.i(TAG, "WeMessageApi Entry 初始化...")

            // 初始化 Unsafe 反射
            initUnsafe()

            // 初始化基础组件
            netSceneSendMsgClass = dexClassNetSceneSendMsg.clazz
            getSendMsgObjectMethod = dexMethodGetSendMsgObject.method
            postToQueueMethod = dexMethodPostToQueue.method
            shareFileMethod = dexMethodShareFile.method
            p6Method = dexMethodImageSendEntry.method

            // 初始化 Task (k40.g) 和 CrossParams (d40.i0) 的构造函数
            val taskClazz = dexClassImageTask.clazz
            // k40.g 的构造函数签名: (String, int, String, String, d40.i0) -> 共 5 个参数
            taskConstructor = taskClazz.declaredConstructors.firstOrNull { it.parameterCount == 5 }
            taskConstructor?.isAccessible = true

            if (taskConstructor != null) {
                // 获取 d40.i0 的 Class: 它是 k40.g 构造函数的第 5 个参数
                crossParamsClass = taskConstructor!!.parameterTypes[4]

                // d40.i0 是标准 Java Bean，通常有无参构造
                crossParamsConstructor = crossParamsClass?.declaredConstructors?.firstOrNull { it.parameterCount == 0 }
                crossParamsConstructor?.isAccessible = true

                WeLogger.i(TAG, "构造函数定位成功: Task=${taskConstructor != null}, CrossParams=${crossParamsConstructor != null}")
            } else {
                WeLogger.e(TAG, "警告: 未找到 k40.g 的 5 参数构造函数，SendImage 可能不可用")
            }

            // 定位 Map 字段 (imageMetadataMapField)
            // k40.g 中只有一个 Map 类型的字段
            imageMetadataMapField = taskClazz.declaredFields.firstOrNull {
                Map::class.java.isAssignableFrom(it.type)
            }
            imageMetadataMapField?.isAccessible = true

            if (imageMetadataMapField != null) {
                WeLogger.i(TAG, "Native发图字段锁定: ${imageMetadataMapField?.name}")
            }

            // 初始化文件发送组件
            try {
                wxFileObjectClass = classLoader.loadClass("com.tencent.mm.opensdk.modelmsg.WXFileObject")
                wxMediaMessageClass = classLoader.loadClass("com.tencent.mm.opensdk.modelmsg.WXMediaMessage")
            } catch (e: Exception) {
                WeLogger.e(TAG, "初始化文件发送组件时失败", e)
            }

            try {
                INSTANCE = this

                // 初始化服务获取逻辑
                bindServiceFramework()
                // 嗅探图片业务接口与方法
                bindImageBusinessLogic()

                WeLogger.i(TAG, "WeMessageApi 全动态链路初始化成功")
            } catch (e: Exception) {
                WeLogger.e(TAG, "Entry 初始化失败", e)
            }


            WeLogger.i(TAG, "WeMessageApi 初始化完毕")
        } catch (e: Exception) {
            WeLogger.e(TAG, "Entry 初始化异常", e)
        }
    }

    /**
     * 初始化 Unsafe 反射
     * （绕过编译检查）
     */
    @SuppressLint("DiscouragedPrivateApi")
    private fun initUnsafe() {
        try {
            val unsafeClass = Class.forName("sun.misc.Unsafe")
            val theUnsafeField = unsafeClass.getDeclaredField("theUnsafe")
            theUnsafeField.isAccessible = true
            unsafeInstance = theUnsafeField.get(null)

            // 预加载 allocateInstance 方法
            allocateInstanceMethod = unsafeClass.getMethod("allocateInstance", Class::class.java)
            WeLogger.i(TAG, "Unsafe 能力已就绪")
        } catch (e: Exception) {
            WeLogger.e(TAG, "Unsafe 获取失败", e)
        }
    }

    /** 发送图片消息 */
    fun sendImage(toUser: String, imgPath: String): Boolean {
        return try {
            val apiInterface = imageServiceApiClass ?: return false
            val taskClass = dexClassImageTask.clazz

            // 动态获取单例
            val serviceObj = getServiceMethod?.invoke(null, apiInterface) ?: return false

            // 动态构造 CrossParams
            val paramsClass = crossParamsClass ?: return false
            val paramsObj = XposedHelpers.newInstance(paramsClass)
            assignValueToFirstFieldByType(paramsObj, Int::class.javaPrimitiveType!!, 4)

            // 构造任务对象
            val taskObj = XposedHelpers.newInstance(taskClass, imgPath, 0, getSelfWxid(), toUser, paramsObj)
            assignValueToLastFieldByType(taskObj, String::class.java, "media_generate_send_img")

            // 执行异步发送
            sendImageMethod?.invoke(serviceObj, taskObj)

            WeLogger.i(TAG, "[sendImage] 任务已提交: $toUser")
            true
        } catch (e: Exception) {
            WeLogger.e(TAG, "[sendImage] 图片发送流程失败", e)
            false
        }
    }


    /** 发送文本消息 */
    fun sendText(toUser: String, text: String): Boolean {
        return try {
            val sendMsgObject = getSendMsgObjectMethod?.invoke(null) ?: return false
            val constructor = netSceneSendMsgClass?.getConstructor(
                String::class.java, String::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Any::class.java
            ) ?: return false
            val msgObj = constructor.newInstance(toUser, text, 1, 0, null)
            postToQueueMethod?.invoke(sendMsgObject, msgObj) as? Boolean ?: false
        } catch (e: Exception) {
            WeLogger.e(TAG, "Text发送失败", e)
            false
        }
    }

    /** 发送文件消息 */
    fun sendFile(talker: String, filePath: String, title: String, appid: String? = null): Boolean {
        return try {
            if (shareFileMethod == null || wxFileObjectClass == null || wxMediaMessageClass == null) return false
            val fileObject = wxFileObjectClass?.newInstance() ?: return false
            wxFileObjectClass?.getField("filePath")?.set(fileObject, filePath)
            val mediaMessage = wxMediaMessageClass?.newInstance() ?: return false
            wxMediaMessageClass?.getField("mediaObject")?.set(mediaMessage, fileObject)
            wxMediaMessageClass?.getField("title")?.set(mediaMessage, title)
            shareFileMethod?.invoke(null, mediaMessage, appid ?: "", "", talker, 2, null)
            true
        } catch (e: Exception) {
            WeLogger.e(TAG, "File 发送失败", e)
            false
        }
    }

    fun getSelfWxid(): String {
        return getSelfWxidMethod?.invoke(null) as? String ?: ""
    }

    private fun bindServiceFramework() {
        val smClazz = dexClassServiceManager.clazz
        getServiceMethod = smClazz.declaredMethods.firstOrNull {
            Modifier.isStatic(it.modifiers) && it.parameterCount == 1 && it.parameterTypes[0] == Class::class.java
        }

        val clClazz = dexClassConfigLogic.clazz
        getSelfWxidMethod = clClazz.declaredMethods.firstOrNull {
            Modifier.isStatic(it.modifiers) && it.parameterCount == 0 && it.returnType == String::class.java && it.name.length <= 2
        }
    }

    private fun bindImageBusinessLogic() {
        val implClazz = dexClassImageServiceImpl.clazz
        val taskClazz = dexClassImageTask.clazz

        // 自动提取 Api 接口
        imageServiceApiClass = implClazz.interfaces.firstOrNull {
            !it.name.startsWith("java.") && !it.name.startsWith("android.")
        }

        // 动态嗅探发送方法 (参数是 Task, 返回值是 Flow)
        sendImageMethod = implClazz.declaredMethods.firstOrNull { m ->
            m.parameterCount == 1 &&
                    m.parameterTypes[0] == taskClazz &&
                    m.returnType.name.contains("flow", ignoreCase = true)
        }

        // 动态确定 CrossParams 类型
        taskClazz.declaredConstructors.firstOrNull { it.parameterCount == 5 }?.let {
            crossParamsClass = it.parameterTypes[4]
        }
    }

    private fun assignValueToFirstFieldByType(obj: Any, type: Class<*>, value: Any) {
        obj.javaClass.declaredFields.firstOrNull { it.type == type }?.let {
            it.isAccessible = true
            it.set(obj, value)
        }
    }

    private fun assignValueToLastFieldByType(obj: Any, type: Class<*>, value: Any) {
        obj.javaClass.declaredFields.lastOrNull { it.type == type }?.let {
            it.isAccessible = true
            it.set(obj, value)
        }
    }
}