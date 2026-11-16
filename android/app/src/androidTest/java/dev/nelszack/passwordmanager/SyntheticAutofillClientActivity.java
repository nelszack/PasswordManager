package dev.nelszack.passwordmanager;

/** Framework-only Java: the test APK also runs outside instrumentation's target classloader. */
public class SyntheticAutofillClientActivity extends android.app.Activity {
    private android.widget.EditText user;
    private android.widget.EditText password;
    private final android.content.BroadcastReceiver control = new android.content.BroadcastReceiver() {
        @Override public void onReceive(android.content.Context context, android.content.Intent intent) {
            if ("dev.nelszack.passwordmanager.TEST_CHECK_CLIENT".equals(intent.getAction())) {
                // Return only assertion bits, never field values.
                setResultCode((user != null && "synthetic-inline-user".equals(user.getText().toString()) ? 1 : 0)
                    | (password != null && "synthetic-password".equals(password.getText().toString()) ? 2 : 0));
            } else finish();
        }
    };
    @Override protected void onDestroy() { unregisterReceiver(control); super.onDestroy(); }
    // Android 28–32 have no exported receiver flag requirement. Test-only controls.
    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    @Override protected void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        android.content.IntentFilter filter = new android.content.IntentFilter("dev.nelszack.passwordmanager.TEST_FINISH_CLIENT");
        filter.addAction("dev.nelszack.passwordmanager.TEST_CHECK_CLIENT");
        if (android.os.Build.VERSION.SDK_INT >= 33) registerReceiver(control, filter, RECEIVER_EXPORTED);
        else registerReceiver(control, filter);
        android.widget.LinearLayout container = new android.widget.LinearLayout(this);
        container.setOrientation(android.widget.LinearLayout.VERTICAL);
        container.setPadding(32, 64, 32, 32);
        android.widget.TextView title = new android.widget.TextView(this);
        title.setText("Synthetic autofill test");
        container.addView(title);
        user = new android.widget.EditText(this);
        user.setHint("Synthetic username");
        user.setInputType(android.text.InputType.TYPE_CLASS_TEXT);
        user.setAutofillHints(android.view.View.AUTOFILL_HINT_USERNAME);
        user.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_YES);
        container.addView(user);
        password = new android.widget.EditText(this);
        password.setHint("Synthetic password");
        password.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setAutofillHints(android.view.View.AUTOFILL_HINT_PASSWORD);
        password.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_YES);
        container.addView(password);
        android.widget.Button request = new android.widget.Button(this);
        request.setText("Request test suggestions");
        request.setOnClickListener(view -> {
            user.requestFocus();
            getSystemService(android.view.inputmethod.InputMethodManager.class).showSoftInput(user, 0);
            getSystemService(android.view.autofill.AutofillManager.class).requestAutofill(user);
        });
        container.addView(request);
        setContentView(container);
    }
}
