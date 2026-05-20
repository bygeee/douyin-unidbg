package com.ttnet.org.chromium.base;

public final class JNIUtils {

    private JNIUtils() {
    }

    public static ClassLoader getSplitClassLoader(String splitName) {
        System.out.println("JNIUtils.getSplitClassLoader called, split=" + splitName);
        return JNIUtils.class.getClassLoader();
    }
}
