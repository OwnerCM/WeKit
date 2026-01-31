package moe.ouom.wekit.hooks.sdk.api

import android.annotation.SuppressLint
import android.database.Cursor
import moe.ouom.wekit.core.dsl.dexClass
import moe.ouom.wekit.core.dsl.dexMethod
import moe.ouom.wekit.core.model.ApiHookItem
import moe.ouom.wekit.dexkit.intf.IDexFind
import moe.ouom.wekit.hooks.core.annotation.HookItem
import moe.ouom.wekit.util.common.SyncUtils
import moe.ouom.wekit.util.log.WeLogger
import org.luckypray.dexkit.DexKitBridge
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * 微信数据库 API
 */
@SuppressLint("DiscouragedApi")
@HookItem(path = "API/数据库服务", desc = "提供数据库直接查询与数据导出能力")
class WeDatabaseApi : ApiHookItem(), IDexFind {
    // MMKernel 类
    private val dexClassKernel by dexClass()

    // Kernel.storage()
    private val dexMethodGetStorage by dexMethod()

    // -------------------------------------------------------------------------------------
    // 运行时缓存
    // -------------------------------------------------------------------------------------
    private var getStorageMethod: Method? = null

    // 运行时缓存
    @Volatile
    private var wcdbInstance: Any? = null
    private var rawQueryMethod: Method? = null

    companion object {
        private const val TAG = "WeDatabaseApi"
        private const val WCDB_CLASS_NAME = "com.tencent.wcdb.database.SQLiteDatabase"

        @SuppressLint("StaticFieldLeak")
        var INSTANCE: WeDatabaseApi? = null
    }

    @SuppressLint("NonUniqueDexKitData")
    override fun dexFind(dexKit: DexKitBridge): Map<String, String> {
        val descriptors = mutableMapOf<String, String>()

        try {
            // 如果缓存生效，框架可能不会执行到这里，或者只执行未命中的部分
            WeLogger.i(TAG, ">>>> 校验数据库 API 缓存 (Process: ${SyncUtils.getProcessName()}) <<<<")

            // 定位 MMKernel
            dexClassKernel.find(dexKit, descriptors) {
                matcher {
                    usingStrings("MicroMsg.MMKernel", "Initialize skeleton")
                }
            }

            val kernelDesc = descriptors[dexClassKernel.key]
            if (kernelDesc != null) {
                // 定位 storage() 方法
                dexMethodGetStorage.find(dexKit, descriptors, true) {
                    matcher {
                        declaredClass = kernelDesc
                        modifiers = Modifier.PUBLIC or Modifier.STATIC
                        paramCount = 0
                        usingStrings("mCoreStorage not initialized!")
                    }
                }
            }
        } catch (e: Exception) {
            WeLogger.e(TAG, "DexKit 查找流程异常", e)
        }
        return descriptors
    }

    override fun entry(classLoader: ClassLoader) {
        try {
            INSTANCE = this
            getStorageMethod = dexMethodGetStorage.method

            // 尝试预热数据库引用
            initializeDatabase()

        } catch (e: Exception) {
            WeLogger.e(TAG, "Entry 初始化异常", e)
        }
    }

    /**
     * 核心初始化逻辑
     */
    @Synchronized
    private fun initializeDatabase(): Boolean {
        if (wcdbInstance != null && rawQueryMethod != null) return true

        try {
            // 获取 Storage 实例
            val storageObj = getStorageMethod?.invoke(null) ?: run {
                // 此时可能账号未登录，属于正常情况，静默失败
                return false
            }

            // 在 Storage 中寻找 Wrapper
            val wrapperObj = findDbWrapper(storageObj)
            if (wrapperObj == null) {
                WeLogger.w(TAG, "初始化: 未找到 Wrapper (可能时机过早)")
                return false
            }

            // 获取 WCDB 实例
            val dbInstance = getWcdbFromWrapper(wrapperObj)
            if (dbInstance == null) {
                WeLogger.w(TAG, "初始化: 未找到 WCDB 实例")
                return false
            }

            // 获取 rawQuery 方法并缓存
            val rawQuery = findRawQueryMethod(dbInstance.javaClass)
            if (rawQuery != null) {
                wcdbInstance = dbInstance
                rawQueryMethod = rawQuery
                WeLogger.i(TAG, "数据库 API 就绪")
                return true
            }

        } catch (e: Exception) {
            WeLogger.e(TAG, "数据库初始化失败", e)
        }
        return false
    }

    /**
     * 快速查找 Wrapper
     */
    private fun findDbWrapper(storageObj: Any): Any? {
        val fields = storageObj.javaClass.declaredFields
        for (field in fields) {
            try {
                field.isAccessible = true
                val obj = field.get(storageObj) ?: continue

                val typeName = obj.javaClass.name
                if (typeName.startsWith("java.") || typeName.startsWith("android.")) continue

                if (checkMethodFeature(obj) || checkStringFeature(obj)) {
                    return obj
                }
            } catch (_: Throwable) {}
        }
        return null
    }

    /**
     * 检查是否有 "MicroMsg.SqliteDB" 字符串
     */
    private fun checkStringFeature(obj: Any): Boolean {
        return try {
            obj.javaClass.declaredFields.any {
                it.isAccessible = true
                it.type == String::class.java && it.get(obj) == "MicroMsg.SqliteDB"
            }
        } catch (_: Exception) { false }
    }

    /**
     * 检查是否有无参方法返回 SQLiteDatabase
     */
    private fun checkMethodFeature(obj: Any): Boolean {
        return try {
            obj.javaClass.declaredMethods.any {
                it.parameterCount == 0 && it.returnType.name == WCDB_CLASS_NAME
            }
        } catch (_: Exception) { false }
    }

    private fun getWcdbFromWrapper(wrapperObj: Any): Any? {
        val methods = wrapperObj.javaClass.declaredMethods
        for (method in methods) {
            if (method.parameterCount == 0 &&
                method.returnType.name == WCDB_CLASS_NAME) {
                try {
                    method.isAccessible = true
                    val db = method.invoke(wrapperObj)
                    if (db != null) return db
                } catch (_: Exception) {}
            }
        }
        return null
    }

    private fun findRawQueryMethod(clazz: Class<*>): Method? {
        try {
            return clazz.getMethod("rawQuery", String::class.java, Array<Any>::class.java)
        } catch (_: Exception) {}
        try {
            return clazz.getMethod("rawQuery", String::class.java, Array<String>::class.java)
        } catch (_: Exception) {}
        return null
    }

    // -------------------------------------------------------------------------------------
    // 业务接口
    // -------------------------------------------------------------------------------------

    fun executeQuery(sql: String): List<Map<String, Any?>> {
        val result = mutableListOf<Map<String, Any?>>()
        // 每次执行前检查一次初始化
        if (!initializeDatabase()) return result

        var cursor: Cursor? = null
        try {
            cursor = rawQueryMethod?.invoke(wcdbInstance, sql, null) as? Cursor

            if (cursor != null && cursor.moveToFirst()) {
                val columnNames = cursor.columnNames
                do {
                    val row = HashMap<String, Any?>()
                    for (i in columnNames.indices) {
                        val name = columnNames[i]
                        val type = cursor.getType(i)
                        val value = when (type) {
                            Cursor.FIELD_TYPE_NULL -> null
                            Cursor.FIELD_TYPE_INTEGER -> cursor.getLong(i)
                            Cursor.FIELD_TYPE_FLOAT -> cursor.getDouble(i)
                            Cursor.FIELD_TYPE_STRING -> cursor.getString(i)
                            Cursor.FIELD_TYPE_BLOB -> cursor.getBlob(i)
                            else -> cursor.getString(i)
                        }
                        row[name] = value
                    }
                    result.add(row)
                } while (cursor.moveToNext())
            }
        } catch (e: Exception) {
            WeLogger.e(TAG, "SQL执行异常: ${e.message}")
        } finally {
            cursor?.close()
        }
        return result
    }

    fun getFriendList(): List<Map<String, Any?>> {
        val sql = """
            select 
                r.username, r.alias, r.conRemark, r.nickname, 
                r.pyInitial, r.quanPin, r.encryptUserName, i.reserved2 as avatarUrl
            from rcontact r 
            INNER JOIN img_flag i on r.username = i.username 
            where r.type&2=2 and i.lastupdatetime > 0
        """.trimIndent()
        return executeQuery(sql)
    }


    fun getAvatarUrl(wxid: String): String {
        if (wxid.isEmpty()) return ""
        val sql = "SELECT i.reserved2 AS avatarUrl FROM img_flag i WHERE i.username = '$wxid'"
        val result = executeQuery(sql)
        return if (result.isNotEmpty()) {
            result[0]["avatarUrl"] as? String ?: ""
        } else {
            ""
        }
    }

    fun getMessages(wxid: String, page: Int = 1, pageSize: Int = 20): List<Map<String, Any?>> {
        if (wxid.isEmpty()) return emptyList()
        val offset = (page - 1) * pageSize
        val sql = "select * from message where talker='$wxid' order by createTime desc limit $pageSize offset $offset"
        return executeQuery(sql)
    }
}