<?php

/**
 * Userli Aliases
 *
 * Update user identities from userli aliases API at login
 *
 * @version 0.1
 * @author systemli
 */

declare(strict_types=1);

class userli extends rcube_plugin
{
    public $task = "login";
    private string $pass = "";

    public function init(): void
    {
        // Before the user login on the IMAP server is performed.
        $this->add_hook("authenticate", [$this, "authenticate_store_pass"]);
        // Triggered after a user successfully logged in
        $this->add_hook("login_after", [
            $this,
            "login_after_update_identities",
        ]);
    }

    /**
     * Store user password during authentication
     */
    public function authenticate_store_pass($args): void
    {
        $this->pass = $args["pass"];
    }

    /**
     * Update identities from userli aliases after login
     */
    public function login_after_update_identities(): void
    {
        $rcmail = rcmail::get_instance();
        $this->load_config();

        // Get list of userli aliases
        $client = $rcmail->get_http_client();
        try {
            $response = $client->request(
                'POST',
                $rcmail->config->get("userli_url") . '/api/roundcube/aliases',
                [
                    "verify" => $rcmail->config->get(
                        "userli_ssl_verify",
                    ),
                    "json" => [
                        "email" => $rcmail->user->get_username(),
                        "password" => $this->pass,
                    ],
                     "headers" => [
                         'X-API-Token' => $rcmail->config->get("userli_token")
                     ],
                ],
            );
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
}
