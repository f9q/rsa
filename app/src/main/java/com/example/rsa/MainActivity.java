package com.example.rsa;

import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import butterknife.BindView;
import butterknife.ButterKnife;


public class MainActivity extends AppCompatActivity {

    @BindView(R.id.result)  TextView    result;
    @BindView(R.id.data)    EditText    data;

    private RSAPublicKey    publicKey;
    private RSAPrivateKey   privateKey;


    public void onLoadPublicKey(View view){

        loadPrivateKey();

        String key64 = RSAUtil.loadKeyFromAssets("rsa_public_key.pem");
        result.setText("1.公钥经base64编码 : \n" + key64 + "\n");

        byte key[] = decodeBase64(key64);

        result.append("2.公钥base64解码后 : \n" + new String(key) + "\n");
        try {
            publicKey = (RSAPublicKey) RSAUtil.getPublicKey(key);
            result.append("3.最终公钥为: \n" + publicKey.toString() + "\n");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void loadPrivateKey(){
        String key64 = RSAUtil.loadKeyFromAssets("rsa_pkcs8_private_key.pem");
        Log.e("MainActivity", "loadPrivateKey: " + key64 );
        byte key[] = decodeBase64(key64);
        try {
            privateKey = (RSAPrivateKey) RSAUtil.getPrivateKey(key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public void test1(View view){
        String data = this.data.getText().toString();
        Log.e("MainActivity", "test1: source = " + data );
        try {
            result.setText("1.原数据为：\n" + data );

            long begin,end;
            begin = SystemClock.elapsedRealtime();
            byte encrypted[] = RSAUtil.encryptByPrivateKey(data.getBytes(),privateKey);
            end = SystemClock.elapsedRealtime();
            result.append("\n2.私钥加密，加密后数据为： 耗时 "  + (end - begin) + " ms \n" + new String(encrypted) );

            byte signed[] = RSAUtil.sign(data.getBytes(),privateKey);
            result.append("\n3.私钥签名，签名后数据为：\n" + new String(signed));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(encrypted);
            bos.write(signed);

            String en64 = encodeBase64(bos.toByteArray());
            bos.close();
            result.append("\n4.Base64编码(加密数据+签名)：\n" + en64);



            //read
            byte de64[] = decodeBase64(en64);
            result.append("\n5.Base64解码：\n" + new String(de64));

            ByteArrayInputStream bis = new ByteArrayInputStream(de64);
            byte encrypted2[] = new byte[encrypted.length ];
            bis.read(encrypted2);

            begin = SystemClock.elapsedRealtime();
            byte decrypt[] = RSAUtil.decryptByPublicKey(encrypted2,publicKey);
            end = SystemClock.elapsedRealtime();

            result.append("\n6.公钥解密，解密后数据为：耗时 "  + (end - begin) + " ms \n" + new String(decrypt));

            byte signed2[] = new byte[signed.length];
            bis.read(signed2);
            bis.close();
            boolean ret = RSAUtil.verify(data.getBytes(),signed2,publicKey);
            result.append("\n7.公钥验证，结果为： " + ret);


        } catch (Exception e) {
            e.printStackTrace();
            result.append("\n\n异常信息：" + e.getMessage());
        }

    }
    public void test2(View view){
        String data = this.data.getText().toString();
/*

        data = "B5oYHN8e9SpdAHZs46lcGXgCtvLjONXousdBht8OO8aP5C4oPxi/b9+2X/ZkpUuY"
                + "B5oYHN8e9SpdAHZs46lcGXgCtvLjONXousdBht8OO8aP5C4oPxi/b9+2X/ZkpUuR"
                + "B5oYHN8e9SpdAHZs46lcGXgCtvLjONXousdBht8OO8aP5C4oPxi/b9+2X/ZkpUuZ"
                + "B5oYHN8e9SpdAHZs46lcGXgCtvLjONXousdBht8OO8aP5C4oPxi/b9+2X/ZkpUuZ"
                + "B5oYHN8e9SpdAHZs46lcGXgCtvLjONXousdBht8OO8aP5C4oPxi/b9+2X/ZkpUuZ"
                + "B5oYHN8e9SpdAHZs46lcGXgCtvLONXousdBht8OO8aP55C4oPxier"
                ;
*/

        Log.e("MainActivity", "test2: source = " + data );
        try {
            result.setText("1.原数据为：\n" + data);

            long begin,end;
            begin = SystemClock.elapsedRealtime();
            byte encrypt[] = RSAUtil.encryptByPublicKey(data.getBytes(),publicKey);
            end = SystemClock.elapsedRealtime();

            result.append("\n2.公钥加密后数据为：： 耗时 "  + (end - begin) + " ms \n" + new String(encrypt));

            String en64 = encodeBase64(encrypt);
            result.append("\n3.Base64编码：\n" + en64 );

            byte de64[] = decodeBase64(en64);

            result.append("\n4.Base64解码：\n" + new String(de64) );


            begin = SystemClock.elapsedRealtime();
            byte decrypt[] = RSAUtil.decryptByPrivateKey(de64,privateKey);
            end = SystemClock.elapsedRealtime();

            result.append("\n5.私钥解密后数据为：：耗时 "  + (end - begin) + " ms \n" + new String(decrypt) );


        } catch (Exception e) {
            e.printStackTrace();
            result.append("\n\n异常信息：" + e.getMessage());
        }

    }

    String encodeBase64(byte[] data) {
        String b64 = Base64.encodeToString(data, Base64.DEFAULT);
        return b64;
    }

    byte[] decodeBase64(String b64) {
        byte[] ret = Base64.decode(b64, Base64.DEFAULT);
        return ret;
    }

    private void javaKey(){
        KeyPair kp = RSAUtil.init(RSAUtil.DEFAULT_KEY_SIZE);
        publicKey = (RSAPublicKey) kp.getPublic();
        privateKey = (RSAPrivateKey) kp.getPrivate();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
    }
}
