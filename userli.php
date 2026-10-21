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
    }

    public function startup(array $args): array
    {
        $rcmail = rcmail::get_instance();

        if ($args["task"] === "login") {
            $this->pending = $_SESSION["userli_2fa"] ?? null;
            unset($_SESSION["userli_2fa"]);
        }

        if (empty($_SESSION["user_id"])) {
            return $args;
        }

        if ($args["task"] === "logout") {
            if ($rcmail->check_request(rcube_utils::INPUT_GET | rcube_utils::INPUT_POST)) {
                $this->request_api("logout", [
                    "email" => $rcmail->get_user_name(),
                    "password" => $rcmail->get_user_password(),
                ]);
            }

            return $args;
        }

        // Dovecot rejects the webmail credential after it expired, so end the session with it
        if (isset($_SESSION["userli_expires"]) && $_SESSION["userli_expires"] <= time()) {
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
            "inputmode" => "numeric",
            "autofocus" => "autofocus",
        ]);

        $args["hidden"]["user"] = $user->show();
        $args["inputs"] = [
            "code" => [
                "title" => html::label("rcmloginuserlicode", html::quote($this->gettext("twofactor_code"))),
                "content" => $code->show(),
            ],
        ];

        return $args;
    }

    /**
     * Exchange the password (and 2FA code) for a webmail credential, which is used for IMAP and SMTP
     */
    public function authenticate(array $args): array
    {
        $rcmail = rcmail::get_instance();
        $code = trim((string) rcube_utils::get_input_string("_userli_code", rcube_utils::INPUT_POST));
        $pending = $this->pending;
        $this->pending = null;

        if (
            $code !== "" && $pending !== null && $pending["user"] === $args["user"]
            && $pending["time"] + self::PENDING_LIFETIME > time()
        ) {
            $args["pass"] = (string) $rcmail->decrypt($pending["pass"]);
        } else {
            $code = "";
            $pending = null;
        }

        // The aliases API needs the password, the credential is rejected there
        $this->pass = $args["pass"];

        $response = $this->request_api("login", [
            "email" => $args["user"],
            "password" => $args["pass"],
            "code" => $code,
        ]);

        // Userli without webmail login: Dovecot checks the password as before
        if ($response !== null && $response["status"] === 404) {
            return $args;
        }

        if ($response !== null && $response["status"] === 200 && !empty($response["body"]["password"])) {
            $args["pass"] = $response["body"]["password"];
            $expires = strtotime((string) ($response["body"]["expiresAt"] ?? ""));
            $this->expires = $expires === false ? null : $expires;

            return $args;
        }

        $args["abort"] = true;

        if ($response === null || $response["status"] !== 401) {
            $args["error"] = "userli.login_unavailable";
        } elseif ($pending !== null) {
            // Wrong code: let the user try again until the pending login expires
            $this->pending = $pending;
            $args["error"] = "userli.twofactor_invalid";
        } elseif (($response["body"]["message"] ?? "") === "twofactor required") {
            $this->pending = [
                "user" => $args["user"],
                "pass" => $rcmail->encrypt($args["pass"]),
                "time" => time(),
            ];
            $args["error"] = "userli.twofactor_required";
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
