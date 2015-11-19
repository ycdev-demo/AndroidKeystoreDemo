package me.ycdev.android.demo.keystore;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import me.ycdev.android.demo.keystore.utils.AppLogger;
import me.ycdev.android.demo.keystore.utils.IoUtils;

public class KeyChainDemo {
    private static final String TAG = "KeyChainDemo";

    private String mKeyAlias;

    public void installCredentials(Activity cxt, int requestCode) {
        AssetManager assetMgr = cxt.getAssets();
        try {
            // password: android
            InputStream in = assetMgr.open("apk.keystore.p12");
            byte[] keystoreData = IoUtils.readAllBytes(in);
            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_PKCS12, keystoreData);
            cxt.startActivityForResult(installIntent, requestCode);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void requestCredentials(Activity cxt) {
        final Context appContext = cxt.getApplicationContext();
        KeyChain.choosePrivateKeyAlias(cxt,
                new KeyChainAliasCallback() {
                    public void alias(String alias) {
                        AppLogger.d(TAG, "got key alias [" + alias + "]");
                        if (alias != null) {
                            mKeyAlias = alias;
                            new Thread() {
                                @Override
                                public void run() {
                                    checkPrivateKey(appContext);
                                    checkCertificateChain(appContext);
                                }
                            }.start();
                        }
                    }
                },
                new String[]{"RSA", "DSA"}, null, null, -1, null);
    }

    private void checkPrivateKey(Context cxt) {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyChain.getPrivateKey(cxt, mKeyAlias);
            AppLogger.d(TAG, "private key: " + privateKey);
            if (privateKey == null) {
                return;
            }
            AppLogger.d(TAG, "format: " + privateKey.getFormat());
            AppLogger.d(TAG, "alg: " + privateKey.getAlgorithm());
        } catch (KeyChainException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void checkCertificateChain(Context cxt) {
        try {
            X509Certificate[] certificates = KeyChain.getCertificateChain(cxt, mKeyAlias);
            if (certificates == null) {
                return;
            }
            AppLogger.i(TAG, "cert count: " + certificates.length);
            for (X509Certificate cert : certificates) {
                AppLogger.i(TAG, "cert: " + cert);
            }
        } catch (KeyChainException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
