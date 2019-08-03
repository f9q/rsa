package com.example.rsa;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void useAppContext() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("com.example.rsa", appContext.getPackageName());
    }

    @Test
    public void base64(){

        String data = "test";
        String b64 = encodeBase64(data.getBytes());

        byte result [] = decodeBase64(b64);

        String str = new String(result);

        boolean eqs = str.equals(data);
        assertTrue(eqs);
    }


    String encodeBase64(byte[] data) {
        String b64 = Base64.encodeToString(data, Base64.DEFAULT);
        Log.e("MainActivity", "encodeBase64: result = " + b64);
        return b64;
    }

    byte[] decodeBase64(String b64) {

        byte[] ret = Base64.decode(b64, Base64.DEFAULT);
        Log.e("MainActivity", "decodeBase64: result = " + new String(ret));

        return ret;
    }

}
