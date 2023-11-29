package com.example.myapplication;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import android.view.View;
import android.widget.*;

import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    EditText urlEnter;
    Button detect;
    TextView predict;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        urlEnter = findViewById(R.id.url);
        predict = findViewById(R.id.predict);
        detect = findViewById(R.id.detect);

        OkHttpClient okHttpClient = new OkHttpClient();
        detect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    String url = urlEnter.getText().toString();
                    RequestBody formBody = new FormBody.Builder().add("url", url).build();
                    Request request = new Request.Builder().url("http://192.168.110.7:5000/predict").post(formBody).build();
                    okHttpClient.newCall(request).enqueue(new Callback() {
                        @Override
                        public void onFailure(@NonNull Call call, @NonNull IOException e) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    Toast.makeText(MainActivity.this, e.getMessage(), Toast.LENGTH_SHORT).show();
                                }

                            });
                        }

                        @Override
                        public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        String result = response.body().string();
                                        if(result.equals("0")){
                                            predict.setText("Your URL is Safe");
                                        }
                                        else {
                                            predict.setText("Your URL is Suspicious");
                                        }
                                    } catch (IOException e) {
                                        throw new RuntimeException(e);
                                    }
                                }
                            });

                        }
                    });
                } catch (Exception e){

                }
            }
        });
    }
}