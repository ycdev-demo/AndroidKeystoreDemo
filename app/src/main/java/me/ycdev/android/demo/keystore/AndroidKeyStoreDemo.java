package me.ycdev.android.demo.keystore;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;

import me.ycdev.android.demo.keystore.utils.AppLogger;

public class AndroidKeyStoreDemo {
    private static final String TAG = "AndroidKeyStoreDemo";

    private boolean mUserAuth;
    private String mPrivateKeyAlias;
    private String mSecretKeyAlias;
    private KeyguardManager mKeyguardManager;

    public AndroidKeyStoreDemo(Context cxt, boolean needUserAuth,
            String privateKeyAlias, String secretKeyAlias) {
        mUserAuth = needUserAuth;
        mPrivateKeyAlias = privateKeyAlias;
        mSecretKeyAlias = secretKeyAlias;
        mKeyguardManager = (KeyguardManager) cxt.getSystemService(Context.KEYGUARD_SERVICE);
    }

    public void checkAllKeys() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Enumeration<String> allAliases = ks.aliases();
            AppLogger.d(TAG, "list aliases in AndroidKeyStore");
            while (allAliases.hasMoreElements()) {
                String alias = allAliases.nextElement();
                AppLogger.d(TAG, "alias : " + alias);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void generateNewPrivateKey() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            AppLogger.w(TAG, "Not supported, need Android M+");
            return;
        }

        if (mUserAuth && !mKeyguardManager.isKeyguardSecure()) {
            AppLogger.d(TAG, "need keyguard secure for user authentication key use");
            return;
        }

        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    mPrivateKeyAlias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
            builder.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512);
            if (mUserAuth) {
                builder.setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(30);
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(builder.build());
            KeyPair kp = kpg.generateKeyPair();
            AppLogger.d(TAG, "private key: " + kp.getPrivate());
            AppLogger.d(TAG, "public key: " + kp.getPublic());
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void generateNewSecretKey() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            AppLogger.w(TAG, "Not supported, need Android M+");
            return;
        }

        if (mUserAuth && !mKeyguardManager.isKeyguardSecure()) {
            AppLogger.d(TAG, "need keyguard secure for user authentication key use");
            return;
        }

        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    mSecretKeyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
            builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setKeySize(256);
            if (mUserAuth) {
                builder.setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(30);
            }

            KeyGenerator kg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(builder.build());
            SecretKey key = kg.generateKey();
            AppLogger.d(TAG, "secret key: " + key);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void signAndVerify(Activity cxt, int requestCode) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            AppLogger.w(TAG, "Not supported, need Android M+");
            return;
        }

        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            KeyStore.Entry entry = ks.getEntry(mPrivateKeyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                AppLogger.w(TAG, "Not an instance of a PrivateKeyEntry");
                return;
            }

            byte[] data = "hahahaha.....".getBytes();
            KeyStore.PrivateKeyEntry secretEntry = (KeyStore.PrivateKeyEntry) entry;

            // check user auth
            KeyFactory factory = KeyFactory.getInstance(
                    secretEntry.getPrivateKey().getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = factory.getKeySpec(secretEntry.getPrivateKey(), KeyInfo.class);
            if (keyInfo.isUserAuthenticationRequired() && !mKeyguardManager.isKeyguardSecure()) {
                AppLogger.d(TAG, "need keyguard secure for user authentication key use");
                return;
            }

            // sign
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
            s.update(data);
            byte[] signature = s.sign();

            // verify
            Signature s2 = Signature.getInstance("SHA256withECDSA");
            s2.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
            s2.update(data);
            boolean valid = s2.verify(signature);
            AppLogger.d(TAG, "verify result: " + valid);
        } catch (UserNotAuthenticatedException e) {
            showAuthenticationScreen(cxt, requestCode);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void encryptAndDecrypt(Activity cxt, int requestCode) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            AppLogger.w(TAG, "Not supported, need Android M+");
            return;
        }

        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            KeyStore.Entry entry = ks.getEntry(mSecretKeyAlias, null);
            if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                AppLogger.w(TAG, "Not an instance of a SecretKeyEntry");
                return;
            }

            String data = "fofofo...fofofo...fofofo...";
            KeyStore.SecretKeyEntry secretEntry = (KeyStore.SecretKeyEntry) entry;

            // check user auth
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    secretEntry.getSecretKey().getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(secretEntry.getSecretKey(), KeyInfo.class);
            if (keyInfo.isUserAuthenticationRequired() && !mKeyguardManager.isKeyguardSecure()) {
                AppLogger.d(TAG, "need keyguard secure for user authentication key use");
                return;
            }

            // encrypt
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretEntry.getSecretKey());
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            byte[] iv = cipher.getIV();

            // decrypt
            Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher2.init(Cipher.DECRYPT_MODE, secretEntry.getSecretKey(),
                    new IvParameterSpec(iv));
            byte[] decryptedData = cipher2.doFinal(encryptedData);
            String plaintext = new String(decryptedData);
            AppLogger.d(TAG, "decrypted plaintext: " + plaintext + ", success: " + data.equals(plaintext));
        } catch (UserNotAuthenticatedException e) {
            showAuthenticationScreen(cxt, requestCode);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void showAuthenticationScreen(Activity cxt, int requestCode) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            KeyguardManager keyguardMgr = (KeyguardManager) cxt.getSystemService(Context.KEYGUARD_SERVICE);
            Intent intent = keyguardMgr.createConfirmDeviceCredentialIntent(null, null);
            if (intent != null) {
                cxt.startActivityForResult(intent, requestCode);
            }
        }
    }

}
