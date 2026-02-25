/**
 * ZAP Authentication Script Template — GraalVM JS Compatible
 *
 * Works with: ZAP 2.13+ / Java 15+ (GraalVM Nashorn replacement)
 *
 * NASHORN (old)  →  GRAALVM (required)
 * ----------------------------------------------------
 * importPackage(org.example)      →  var Cls = Java.type("org.example.Cls")
 * importClass(org.example.Foo)    →  var Foo = Java.type("org.example.Foo")
 * new java.lang.String("x")       →  Java.type("java.lang.String").valueOf("x")
 *
 * Rename this file to <name>.zst and upload it in the scan UI.
 */

// ── Imports (GraalVM style — no importPackage / importClass) ─────────────────
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader        = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI               = Java.type("org.apache.commons.httpclient.URI");

// ── Required exports ──────────────────────────────────────────────────────────

/**
 * Called by ZAP to perform the actual login.
 * Return the HTTP message that resulted in an authenticated session.
 *
 * @param {ScriptHelper}     helper       - ZAP script helper
 * @param {Map<String,String>} paramsValues - script parameters (see getRequiredParamsNames)
 * @param {AuthenticationCredentials} credentials - user credentials
 */
function authenticate(helper, paramsValues, credentials) {
    var loginUrl  = paramsValues.get("Login URL");
    var username  = credentials.getParam("Username");
    var password  = credentials.getParam("Password");

    // Build POST body — adjust field names to match your login form
    var postBody  = "username=" + encodeURIComponent(username) +
                    "&password=" + encodeURIComponent(password);

    var msg = helper.prepareMessage();

    msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
    msg.getRequestHeader().setURI(new URI(loginUrl, true));
    msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE,
                                     "application/x-www-form-urlencoded");
    msg.getRequestHeader().setContentLength(postBody.length());
    msg.setRequestBody(postBody);

    helper.sendAndReceive(msg, false);   // false = don't follow redirects

    print("[ZAP Auth] Login response: " + msg.getResponseHeader().getStatusCode());
    return msg;
}

/** Parameters that appear in the ZAP UI for this script. */
function getRequiredParamsNames() {
    return ["Login URL"];
}

function getOptionalParamsNames() {
    return [];
}

/** Credential fields shown in the ZAP Users panel. */
function getCredentialsParamsNames() {
    return ["Username", "Password"];
}
