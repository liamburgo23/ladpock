package com.example.notes

import android.webkit.WebView

class WebActivity {
    fun configure(webView: WebView, bridge: Any) {
        webView.settings.javaScriptEnabled = true
        webView.settings.setAllowUniversalAccessFromFileURLs(true)
        webView.addJavascriptInterface(bridge, "Native")
    }
}
