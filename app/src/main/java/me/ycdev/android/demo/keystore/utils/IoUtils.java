package me.ycdev.android.demo.keystore.utils;

import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class IoUtils {

    public static byte[] readAllBytes(@NonNull InputStream is) throws IOException {
        ByteArrayOutputStream bytesBuf = new ByteArrayOutputStream(1024);
        int bytesReaded;
        byte[] buf = new byte[1024];
        while ((bytesReaded = is.read(buf, 0, buf.length)) != -1) {
            bytesBuf.write(buf, 0, bytesReaded);
        }
        return bytesBuf.toByteArray();
    }

}
