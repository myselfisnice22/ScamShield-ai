package com.scamshieldai.app;

import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.util.Base64;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Receives text and screenshots that the user SHARES to ScamShield from
 * other apps (WhatsApp, Messages, Gmail, Gallery...) and hands them to the
 * JavaScript app.
 *
 * JavaScript side:
 *   ShareReceiver.getPending()                 -> share that opened the app
 *   ShareReceiver.addListener("shareReceived") -> share while app is open
 *
 * Result shape: {type: "text", text} | {type: "image", base64, mimeType} | {error}
 */
@CapacitorPlugin(name = "ShareReceiver")
public class ShareReceiverPlugin extends Plugin {

    private static final int MAX_TEXT_CHARS = 5000;
    private static final int MAX_IMAGE_BYTES = 5 * 1024 * 1024;

    private JSObject pending = null;

    @Override
    public void load() {
        Intent intent = getActivity().getIntent();
        pending = readShare(intent);
        if (pending != null) {
            // Stop the same share being handled again (e.g. after rotating the phone).
            getActivity().setIntent(new Intent(Intent.ACTION_MAIN));
        }
    }

    @Override
    protected void handleOnNewIntent(Intent intent) {
        super.handleOnNewIntent(intent);
        JSObject shared = readShare(intent);
        if (shared != null) {
            pending = null;
            notifyListeners("shareReceived", shared, true);
        }
    }

    @PluginMethod
    public void getPending(PluginCall call) {
        JSObject result = pending != null ? pending : new JSObject();
        pending = null;
        call.resolve(result);
    }

    private JSObject readShare(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction()) || intent.getType() == null) {
            return null;
        }
        String type = intent.getType();
        JSObject result = new JSObject();

        if (type.startsWith("text/")) {
            CharSequence text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
            if (text == null || text.length() == 0) {
                return null;
            }
            String value = text.toString();
            if (value.length() > MAX_TEXT_CHARS) {
                value = value.substring(0, MAX_TEXT_CHARS);
            }
            result.put("type", "text");
            result.put("text", value);
            return result;
        }

        if (type.startsWith("image/")) {
            Uri uri = getStreamUri(intent);
            // Only accept content:// links. file:// links could point at this
            // app's own private files, which must never be uploaded.
            if (uri == null || !ContentResolver.SCHEME_CONTENT.equals(uri.getScheme())) {
                result.put("error", "That image could not be opened.");
                return result;
            }
            ContentResolver resolver = getContext().getContentResolver();
            try (InputStream input = resolver.openInputStream(uri)) {
                if (input == null) {
                    result.put("error", "That image could not be opened.");
                    return result;
                }
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] chunk = new byte[16 * 1024];
                int read;
                while ((read = input.read(chunk)) != -1) {
                    buffer.write(chunk, 0, read);
                    if (buffer.size() > MAX_IMAGE_BYTES) {
                        result.put("error", "That screenshot is too large (over 5 MB). Please crop it first.");
                        return result;
                    }
                }
                String mime = resolver.getType(uri);
                result.put("type", "image");
                result.put("mimeType", mime != null ? mime : type);
                result.put("base64", Base64.encodeToString(buffer.toByteArray(), Base64.NO_WRAP));
                return result;
            } catch (Exception e) {
                result.put("error", "That image could not be read.");
                return result;
            }
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    private Uri getStreamUri(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
        }
        return intent.getParcelableExtra(Intent.EXTRA_STREAM);
    }
}
