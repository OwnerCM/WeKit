package moe.ouom.wekit.loader.core;

import androidx.annotation.NonNull;
import androidx.annotation.Keep;

import moe.ouom.wekit.security.SignatureVerifier;
import moe.ouom.wekit.util.log.Logger;

@Keep
public class WeKitNative {

    private static final String TAG = "WeKitNative";
    private static volatile boolean sLibraryLoaded = false;

    public static void setLibraryLoaded() {
        sLibraryLoaded = true;
        Logger.i(TAG, "native library marked as loaded");
    }

    private static native boolean doInit(String signatureHash);

    private static native boolean nativeCheck();

    public static void init(@NonNull String flag) {
        if (!sLibraryLoaded) {
            Logger.e(TAG, "Native library not loaded, verification failed");
            return;
        }
        if (!SignatureVerifier.isSignatureValid()) {
            return;
        }

        try {
            doInit(flag);
        } catch (UnsatisfiedLinkError | Exception e) {
            Logger.e("Native init exception", e);
        }
    }

    public static boolean checkIntegrity() {
        if (!sLibraryLoaded) {
            Logger.e(TAG, "Native library not loaded, integrity check failed");
            return false;
        }

        try {
            return nativeCheck();
        } catch (UnsatisfiedLinkError | Exception e) {
            Logger.e("Native integrity check exception", e);
            return false;
        }
    }

    /**
     * 检查Native库是否已加载
     */
    public static boolean isLibraryLoaded() {
        return sLibraryLoaded;
    }
}