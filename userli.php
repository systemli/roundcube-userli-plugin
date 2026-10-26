<?php

/**
 * Userli
 *
 * Logs in with two-factor authentication through the userli API and
 * updates user identities from userli aliases at login
 *
 * @version 0.2
 * @author systemli
 */

declare(strict_types=1);

class userli extends rcube_plugin
{
    // Seconds a user has to enter the 2FA code after the password was accepted
    private const PENDING_LIFETIME = 300;

    private string $pass = "";
    private ?array $pending = null;
    private ?int $expires = null;
    private ?string $credential = null;
    private bool $twofactor_required = false;

    public function init(): void
    {
        $this->add_texts("localization/");
        // Before the requested action runs, also before the login action resets the session
        $this->add_hook("startup", [$this, "startup"]);
        // Alter loginform content
        $this->add_hook("loginform_content", [$this, "modify_login_form"]);
        // Before the user login on the IMAP server is performed.
        $this->add_hook("authenticate", [$this, "authenticate"]);
        // Triggered after a user successfully logged in
        $this->add_hook("login_after", [
            $this,
            "login_after_update_identities",
        ]);
        // IMAP login failed after userli issued a credential
        $this->add_hook("login_failed", [$this, "login_failed"]);
        // Logout, session timeout or a new login, after Roundcube's own logout actions
        $this->add_hook("session_destroy", [$this, "session_destroy"]);
        // Before the login page is sent, decides between HTTP 401 and 200
        $this->add_hook("unauthenticated", [$this, "unauthenticated"]);
    }

    public function startup(array $args): array
    {
        $rcmail = rcmail::get_instance();

        if ($args["task"] === "login") {
            $pending = $_SESSION["userli_2fa"] ?? null;
            $rcmail->session->remove("userli_2fa");
            $valid = is_array($pending) && $pending["time"] + self::PENDING_LIFETIME > time();
            $cancelled = rcube_utils::get_input_string("_userli_cancel", rcube_utils::INPUT_GET) !== "";
            $this->pending = $valid && !$cancelled ? $pending : null;
        }

        // Dovecot rejects the webmail credential after it expired, so end the session with it
        if (!empty($_SESSION["user_id"]) && isset($_SESSION["userli_expires"]) && $_SESSION["userli_expires"] <= time()) {
            $rcmail->kill_session();
        }

        return $args;
    }

    /**
     * Change the username placeholder and, while a 2FA login is pending, ask for the code
     */
    public function modify_login_form(array $args): array
    {
        $this->api->output->add_script(
            "document.addEventListener('DOMContentLoaded', function() {
                var usernameField = document.getElementById('rcmloginuser');
                if (usernameField) {
                    usernameField.placeholder = 'E-mail';
                }
            });"
        );

        if ($this->pending === null) {
            return $args;
        }

        // Written here because the login action resets the session after the authenticate hook
        $_SESSION["userli_2fa"] = $this->pending;

        $user = new html_hiddenfield(["name" => "_user", "value" => $this->pending["user"]]);
        $code = new html_inputfield([
            "name" => "_userli_code",
            "id" => "rcmloginuserlicode",
            "required" => "required",
            "autocomplete" => "one-time-code",
            "autofocus" => "autofocus",
            "data-icon" => "key",
        ]);

        $args["hidden"]["user"] = $user->show();
        $args["inputs"] = [
            "code" => [
                "title" => html::label("rcmloginuserlicode", html::quote($this->gettext("twofactor_code"))),
                "content" => $code->show(),
            ],
        ];
        $args["buttons"]["userli_cancel"] = [
            "outterclass" => "formbuttons",
            "content" => html::a(["href" => "./?_task=login&_userli_cancel=1"], html::quote($this->gettext("use_another_account"))),
        ];

        return $args;
    }

    /**
     * Exchange the password (and 2FA code) for a webmail credential, which is used for IMAP and SMTP
     */
    public function authenticate(array $args): array
    {
        // Roundcube rejects the request anyway (missing CSRF token or session)
        if (empty($args["valid"])) {
            return $args;
        }

        $rcmail = rcmail::get_instance();
        $code = trim((string) rcube_utils::get_input_string("_userli_code", rcube_utils::INPUT_POST));
        $pending = $this->pending;
        $this->pending = null;

        if ($code !== "") {
            if ($pending === null || $pending["user"] !== $args["user"]) {
                $args["abort"] = true;
                $args["error"] = "userli.twofactor_expired";

                return $args;
            }

            $args["pass"] = (string) $rcmail->decrypt($pending["pass"]);
        } else {
            $pending = null;
        }

        // The aliases API needs the password, the credential is rejected there
        $this->pass = $args["pass"];

        $response = $this->request_api("login", [
            "email" => $args["user"],
            "password" => $args["pass"],
            "code" => $code,
        ]);
        $status = $response["status"] ?? null;
        $body = $response["body"] ?? [];

        if ($status === 404) {
            rcube::write_log("userli", "Login endpoint not found, logging in without 2FA");

            return $args;
        }

        if ($status === 200 && is_string($body["password"] ?? null) && $body["password"] !== "") {
            $this->credential = $body["password"];
            $args["pass"] = $body["password"];
            $expires = is_string($body["expiresAt"] ?? null) ? strtotime($body["expiresAt"]) : false;
            $this->expires = $expires === false ? null : $expires;

            return $args;
        }

        $args["abort"] = true;
        $message = $body["message"] ?? "";

        if ($status === 401 && $pending !== null) {
            // Wrong code: let the user try again until the pending login expires
            $this->pending = $pending;
            $args["error"] = "userli.twofactor_invalid";
        } elseif ($status === 401 && $message === "twofactor required") {
            $this->pending = [
                "user" => $args["user"],
                "pass" => $rcmail->encrypt($args["pass"]),
                "time" => time(),
            ];
            $args["error"] = "userli.twofactor_required";
            $this->twofactor_required = true;
        } elseif ($status === 429) {
            $args["error"] = "userli.too_many_attempts";
        } elseif ($status === 403 && $message === "user password change required") {
            $args["error"] = "userli.password_change_required";
        } elseif ($status !== 401 && $status !== 403) {
            $args["error"] = "userli.login_unavailable";
        }

        return $args;
    }

    /**
     * Answer the code step with 200: the password was right, so brute-force detection must not count it
     */
    public function unauthenticated(array $args): array
    {
        if ($this->twofactor_required) {
            $args["http_code"] = 200;
        }

        return $args;
    }

    /**
     * Revoke a credential that Roundcube could not use
     */
    public function login_failed(array $args): array
    {
        if ($this->credential !== null) {
            $this->request_api("logout", ["email" => $args["user"], "password" => $this->credential]);
            $this->credential = null;
        }

        return $args;
    }

    /**
     * Revoke the webmail credential of the ending session
     */
    public function session_destroy(array $args): array
    {
        $rcmail = rcmail::get_instance();

        if (!empty($_SESSION["user_id"])) {
            $this->request_api("logout", [
                "email" => $rcmail->get_user_name(),
                "password" => $rcmail->get_user_password(),
            ]);
        }

        return $args;
    }

    /**
     * Update identities from userli aliases after login
     */
    public function login_after_update_identities(): void
    {
        $rcmail = rcmail::get_instance();

        if ($this->expires !== null) {
            $_SESSION["userli_expires"] = $this->expires;
        }

        // Get list of userli aliases
        try {
            $response = $this->request("aliases", [
                "email" => $rcmail->user->get_username(),
                "password" => $this->pass,
            ]);
            $response_code = $response->getStatusCode();
            $result = (string) $response->getBody();
        } catch (Exception $e) {
            rcube::raise_error(
                [
                    "code" => 600,
                    "file" => __FILE__,
                    "line" => __LINE__,
                    "message" => "Userli aliases plugin: " . $e->getMessage(),
                ],
                true,
                false,
            );
            return;
        }

        if ($response_code !== 200) {
            rcube::raise_error(
                [
                    "code" => 600,
                    "file" => __FILE__,
                    "line" => __LINE__,
                    "message" =>
                        "Userli aliases plugin: Unexpected response code: " .
                        $response_code,
                ],
                true,
                false,
            );
            return;
        }

        $aliases = [];
        $aliases_json_error = false;
        try {
            $aliases = json_decode(
                $result,
                false,
                512,
                JSON_THROW_ON_ERROR,
            );
        } catch (JsonException) {
            $aliases_json_error = true;
        }

        if ($aliases_json_error || !is_array($aliases)) {
            rcube::raise_error(
                [
                    "code" => 600,
                    "file" => __FILE__,
                    "line" => __LINE__,
                    "message" => "Userli aliases plugin: Unexpected aliases format from userli API",
                ],
                true,
                false,
            );
            return;
        }

        $identities = $rcmail->user->list_emails();

        // Clear up old identities
        $existing_aliases = [];
        foreach ($identities as $identity) {
            if ($identity["email"] === $rcmail->user->get_username()) {
                continue;
            }
            if (!in_array($identity["email"], $aliases, true)) {
                $rcmail->user->delete_identity($identity["identity_id"]);
                continue;
            }
            $existing_aliases[] = $identity["email"];
        }

        // Add new identities
        foreach ($aliases as $alias) {
            if (in_array($alias, $existing_aliases, true)) {
                continue;
            }
            $rcmail->user->insert_identity([
                "user_id" => $rcmail->user->ID,
                "email" => $alias,
                "name" => "",
                "standard" => 0,
            ]);
        }
    }

    /**
     * POST to the userli Roundcube API, without throwing on 4xx/5xx responses
     */
    private function request(string $path, array $data)
    {
        $rcmail = rcmail::get_instance();
        $this->load_config();

        return $rcmail->get_http_client()->request(
            'POST',
            $rcmail->config->get("userli_url") . '/api/roundcube/' . $path,
            [
                "verify" => $rcmail->config->get("userli_ssl_verify"),
                "http_errors" => false,
                "json" => $data,
                "headers" => [
                    'X-API-Token' => $rcmail->config->get("userli_token"),
                ],
            ],
        );
    }

    /**
     * Like request(), but returns status and decoded body, or null and logs the error if userli is unreachable
     */
    private function request_api(string $path, array $data): ?array
    {
        try {
            $response = $this->request($path, $data);
        } catch (Exception $e) {
            rcube::raise_error(
                [
                    "code" => 600,
                    "file" => __FILE__,
                    "line" => __LINE__,
                    "message" => "Userli plugin: " . $e->getMessage(),
                ],
                true,
                false,
            );
            return null;
        }

        $body = json_decode((string) $response->getBody(), true);

        return [
            "status" => $response->getStatusCode(),
            "body" => is_array($body) ? $body : [],
        ];
    }
}
