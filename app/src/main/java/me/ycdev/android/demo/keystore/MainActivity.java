package me.ycdev.android.demo.keystore;

import android.content.Intent;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;

import me.ycdev.android.demo.keystore.utils.AppLogger;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    private static final String TAG = "MainActivity";

    private static final int REQUEST_CODE_INSTALL_KEYSTORE = 100;
    private static final int REQUEST_CODE_USER_AUTHENTICATION_VERIFY = 101;
    private static final int REQUEST_CODE_USER_AUTHENTICATION_ENCRYPT = 102;

    private Button mKeyChainInstallCredentialsBtn;
    private Button mKeyChainRequestCredentialsBtn;

    private Button mKeyStoreListAliasBtn;
    private Button mKeyStoreGeneratePrivateKeyBtn;
    private Button mKeyStoreGenerateSecretKeyBtn;
    private Button mKeyStoreSignVerifyBtn;
    private Button mKeyStoreEncryptDecryptBtn;

    private KeyChainDemo mKeyChainDemo;
    private AndroidKeyStoreDemo mKeyStoreDemo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        mKeyChainInstallCredentialsBtn = (Button) findViewById(R.id.keychain_install_credentials);
        mKeyChainInstallCredentialsBtn.setOnClickListener(this);
        mKeyChainRequestCredentialsBtn = (Button) findViewById(R.id.keychain_request_credentials);
        mKeyChainRequestCredentialsBtn.setOnClickListener(this);

        mKeyStoreListAliasBtn = (Button) findViewById(R.id.keystore_list_aliases);
        mKeyStoreListAliasBtn.setOnClickListener(this);
        mKeyStoreGeneratePrivateKeyBtn = (Button) findViewById(R.id.keystore_generate_private_key);
        mKeyStoreGeneratePrivateKeyBtn.setOnClickListener(this);
        mKeyStoreGenerateSecretKeyBtn = (Button) findViewById(R.id.keystore_generate_secret_key);
        mKeyStoreGenerateSecretKeyBtn.setOnClickListener(this);
        mKeyStoreSignVerifyBtn = (Button) findViewById(R.id.keystore_sign_verify);
        mKeyStoreSignVerifyBtn.setOnClickListener(this);
        mKeyStoreEncryptDecryptBtn = (Button) findViewById(R.id.keystore_encrypt_decrypt);
        mKeyStoreEncryptDecryptBtn.setOnClickListener(this);

        mKeyChainDemo = new KeyChainDemo();
        mKeyStoreDemo = new AndroidKeyStoreDemo(this, true,"privatekey#1", "secretkey#1");
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onClick(View v) {
        if (v == mKeyChainInstallCredentialsBtn) {
            mKeyChainDemo.installCredentials(this, REQUEST_CODE_INSTALL_KEYSTORE);
        } else if (v == mKeyChainRequestCredentialsBtn) {
            mKeyChainDemo.requestCredentials(this);
        } else if (v == mKeyStoreListAliasBtn) {
            mKeyStoreDemo.checkAllKeys();
        } else if (v == mKeyStoreGeneratePrivateKeyBtn) {
            mKeyStoreDemo.generateNewPrivateKey();
        } else if (v == mKeyStoreGenerateSecretKeyBtn) {
            mKeyStoreDemo.generateNewSecretKey();
        } else if (v == mKeyStoreSignVerifyBtn) {
            mKeyStoreDemo.signAndVerify(this, REQUEST_CODE_USER_AUTHENTICATION_VERIFY);
        } else if (v == mKeyStoreEncryptDecryptBtn) {
            mKeyStoreDemo.encryptAndDecrypt(this, REQUEST_CODE_USER_AUTHENTICATION_ENCRYPT);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE_INSTALL_KEYSTORE) {
            if (resultCode == RESULT_OK) {
                AppLogger.i(TAG, "credentials install success");
            } else {
                AppLogger.w(TAG, "credentials install fail");
            }
        } else if (requestCode == REQUEST_CODE_USER_AUTHENTICATION_VERIFY) {
            if (resultCode == RESULT_OK) {
                mKeyStoreDemo.signAndVerify(this, REQUEST_CODE_USER_AUTHENTICATION_VERIFY);
            }
        } else if (requestCode == REQUEST_CODE_USER_AUTHENTICATION_ENCRYPT) {
            if (resultCode == RESULT_OK) {
                mKeyStoreDemo.signAndVerify(this, REQUEST_CODE_USER_AUTHENTICATION_ENCRYPT);
            }
        }
    }
}
