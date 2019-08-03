package com.example.rsa;

import android.app.Application;
import android.content.Context;

public class RsaApp extends Application {

    public static Context context ;

    @Override
    public void onCreate() {
        super.onCreate();
        context = getApplicationContext();

    }
}
