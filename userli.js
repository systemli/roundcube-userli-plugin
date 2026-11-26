/**
 * Userli: sign in with a security key in the two-factor step
 *
 * Passes the options from userli (env userli_webauthn) to the browser and
 * submits the assertion, base64url encoded, in the hidden field _userli_webauthn.
 */

(function () {
    function decode(value) {
        var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
        var binary = atob(base64 + "===".slice((base64.length + 3) % 4));
        return Uint8Array.from(binary, function (c) {
            return c.charCodeAt(0);
        });
    }

    function encode(buffer) {
        var binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function useSecurityKey(button) {
        var options = rcmail.env.userli_webauthn;
        var field = document.getElementById("rcmloginuserliwebauthn");
        var form = field.form;
        var publicKey = Object.assign({}, options, {
            challenge: decode(options.challenge),
            allowCredentials: (options.allowCredentials || []).map(function (credential) {
                return Object.assign({}, credential, { id: decode(credential.id) });
            }),
        });

        button.disabled = true;
        navigator.credentials
            .get({ publicKey: publicKey })
            .then(function (credential) {
                var response = credential.response;
                field.value = JSON.stringify({
                    credentialId: encode(credential.rawId),
                    clientDataJSON: encode(response.clientDataJSON),
                    authenticatorData: encode(response.authenticatorData),
                    signature: encode(response.signature),
                    userHandle: response.userHandle ? encode(response.userHandle) : null,
                });

                // The code is not needed with a security key
                if (form.elements._userli_code) {
                    form.elements._userli_code.required = false;
                    form.elements._userli_code.value = "";
                }

                // Like the submit button, so Roundcube shows its loading state
                if (form.requestSubmit) {
                    form.requestSubmit();
                } else {
                    form.submit();
                }
            })
            .catch(function () {
                button.disabled = false;
                rcmail.display_message(rcmail.get_label("webauthn_failed", "userli"), "error");
            });
    }

    function init() {
        var button = document.getElementById("rcmloginuserlikey");
        if (!button) {
            return;
        }

        if (!window.PublicKeyCredential || !rcmail.env.userli_webauthn) {
            button.hidden = true;
            return;
        }

        button.addEventListener("click", function () {
            useSecurityKey(button);
        });
    }

    // Roundcube's init event may have fired before plugin scripts run, the env is set once the DOM is parsed
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
