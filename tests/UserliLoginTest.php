<?php

/**
 * Unit tests for the 2FA login of the userli plugin
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../userli.php';

class FakeResponse
{
    public function __construct(private int $status, private array $body = [])
    {
    }

    public function getStatusCode(): int
    {
        return $this->status;
    }

    public function getBody(): string
    {
        return json_encode($this->body);
    }
}

class FakeClient
{
    public array $calls = [];

    /** @param array<FakeResponse|Exception> $responses */
    public function __construct(private array $responses)
    {
    }

    public function request(string $method, string $url, array $options)
    {
        $this->calls[] = ['url' => $url, 'json' => $options['json'], 'http_errors' => $options['http_errors']];
        $response = array_shift($this->responses);
        if ($response instanceof Exception) {
            throw $response;
        }
        return $response;
    }
}

class UserliLoginTest extends TestCase
{
    private userli $plugin;
    private rcmail $rcmail;

    protected function setUp(): void
    {
        $_SESSION = [];
        $_POST = [];

        $this->plugin = new userli();
        $this->rcmail = rcmail::get_instance();
        $this->rcmail->requestValid = true;
        $this->rcmail->sessionKilled = false;

        $config = $this->getMockBuilder(stdClass::class)->addMethods(['get'])->getMock();
        $config->method('get')->willReturnCallback(static fn ($key) => [
            'userli_url' => 'https://users.example.org',
            'userli_ssl_verify' => true,
            'userli_token' => 'token',
        ][$key] ?? null);
        $this->rcmail->config = $config;
    }

    private function client(FakeResponse|Exception ...$responses): FakeClient
    {
        $client = new FakeClient($responses);
        $this->rcmail->set_http_client($client);
        return $client;
    }

    private function login(string $user, string $pass): array
    {
        return $this->plugin->authenticate(['user' => $user, 'pass' => $pass, 'abort' => false, 'error' => null]);
    }

    public function testInitRegistersLoginHooks(): void
    {
        $this->plugin->init();

        $this->assertArrayHasKey('startup', $this->plugin->getHooks());
        $this->assertArrayHasKey('loginform_content', $this->plugin->getHooks());
    }

    public function testPasswordIsExchangedForWebmailCredential(): void
    {
        $client = $this->client(new FakeResponse(200, ['password' => 'credential', 'expiresAt' => '2030-01-01T00:00:00+00:00']));

        $args = $this->login('user@example.org', 'password');

        $this->assertSame('credential', $args['pass']);
        $this->assertFalse($args['abort']);
        $this->assertSame('https://users.example.org/api/roundcube/login', $client->calls[0]['url']);
        $this->assertSame(['email' => 'user@example.org', 'password' => 'password', 'code' => ''], $client->calls[0]['json']);
        $this->assertFalse($client->calls[0]['http_errors']);
    }

    public function testExpiryIsStoredAndAliasesUseThePassword(): void
    {
        $client = $this->client(
            new FakeResponse(200, ['password' => 'credential', 'expiresAt' => '2030-01-01T00:00:00+00:00']),
            new FakeResponse(200, []),
        );
        $user = $this->getMockBuilder(stdClass::class)->addMethods(['get_username', 'list_emails'])->getMock();
        $user->method('get_username')->willReturn('user@example.org');
        $user->method('list_emails')->willReturn([]);
        $this->rcmail->user = $user;

        $this->login('user@example.org', 'password');
        $this->plugin->login_after_update_identities();

        $this->assertSame(strtotime('2030-01-01T00:00:00+00:00'), $_SESSION['userli_expires']);
        $this->assertSame('https://users.example.org/api/roundcube/aliases', $client->calls[1]['url']);
        $this->assertSame('password', $client->calls[1]['json']['password']);
    }

    public function testOldUserliWithoutLoginEndpointKeepsPassword(): void
    {
        $this->client(new FakeResponse(404));

        $args = $this->login('user@example.org', 'password');

        $this->assertSame('password', $args['pass']);
        $this->assertFalse($args['abort']);
    }

    public function testWrongPasswordFailsLikeBefore(): void
    {
        $this->client(new FakeResponse(401, ['message' => 'authentication failed']));

        $args = $this->login('user@example.org', 'wrong');

        $this->assertTrue($args['abort']);
        $this->assertNull($args['error']);
    }

    public function testUnreachableUserliAbortsLogin(): void
    {
        $this->client(new Exception('Connection refused'));

        $args = $this->login('user@example.org', 'password');

        $this->assertTrue($args['abort']);
        $this->assertSame('userli.login_unavailable', $args['error']);
    }

    public function testTwofactorRequiredShowsCodeForm(): void
    {
        $this->client(new FakeResponse(401, ['message' => 'twofactor required']));

        $args = $this->login('totp@example.org', 'password');
        $form = $this->plugin->modify_login_form(['hidden' => [], 'inputs' => ['user' => [], 'password' => []], 'buttons' => []]);

        $this->assertTrue($args['abort']);
        $this->assertSame('userli.twofactor_required', $args['error']);
        $this->assertSame(['code'], array_keys($form['inputs']));
        $this->assertStringContainsString('name="_userli_code"', $form['inputs']['code']['content']);
        $this->assertStringContainsString('value="totp@example.org"', $form['hidden']['user']);
        $this->assertSame('totp@example.org', $_SESSION['userli_2fa']['user']);
        $this->assertNotSame('password', $_SESSION['userli_2fa']['pass']);
    }

    public function testCodeStepSendsPendingPasswordAndCode(): void
    {
        $_SESSION['userli_2fa'] = ['user' => 'totp@example.org', 'pass' => $this->rcmail->encrypt('password'), 'time' => time()];
        $_POST['_userli_code'] = '123456';
        $client = $this->client(new FakeResponse(200, ['password' => 'credential']));

        $this->plugin->startup(['task' => 'login', 'action' => 'login']);
        $args = $this->login('totp@example.org', '');

        $this->assertSame('credential', $args['pass']);
        $this->assertSame(['email' => 'totp@example.org', 'password' => 'password', 'code' => '123456'], $client->calls[0]['json']);
        $this->assertArrayNotHasKey('userli_2fa', $_SESSION);
    }

    public function testWrongCodeKeepsCodeForm(): void
    {
        $_SESSION['userli_2fa'] = ['user' => 'totp@example.org', 'pass' => $this->rcmail->encrypt('password'), 'time' => time()];
        $_POST['_userli_code'] = '000000';
        $this->client(new FakeResponse(401, ['message' => 'authentication failed']));

        $this->plugin->startup(['task' => 'login', 'action' => 'login']);
        $args = $this->login('totp@example.org', '');
        $this->plugin->modify_login_form(['hidden' => [], 'inputs' => [], 'buttons' => []]);

        $this->assertSame('userli.twofactor_invalid', $args['error']);
        $this->assertSame('totp@example.org', $_SESSION['userli_2fa']['user']);
    }

    public function testExpiredPendingLoginIsIgnored(): void
    {
        $_SESSION['userli_2fa'] = ['user' => 'totp@example.org', 'pass' => $this->rcmail->encrypt('password'), 'time' => time() - 301];
        $_POST['_userli_code'] = '123456';
        $client = $this->client(new FakeResponse(401, ['message' => 'authentication failed']));

        $this->plugin->startup(['task' => 'login', 'action' => 'login']);
        $args = $this->login('totp@example.org', '');

        $this->assertTrue($args['abort']);
        $this->assertSame(['email' => 'totp@example.org', 'password' => '', 'code' => ''], $client->calls[0]['json']);
    }

    public function testPendingLoginOfAnotherUserIsIgnored(): void
    {
        $_SESSION['userli_2fa'] = ['user' => 'totp@example.org', 'pass' => $this->rcmail->encrypt('password'), 'time' => time()];
        $_POST['_userli_code'] = '123456';
        $client = $this->client(new FakeResponse(401, ['message' => 'authentication failed']));

        $this->plugin->startup(['task' => 'login', 'action' => 'login']);
        $this->login('other@example.org', 'guess');

        $this->assertSame(['email' => 'other@example.org', 'password' => 'guess', 'code' => ''], $client->calls[0]['json']);
    }

    public function testLogoutRevokesWebmailCredential(): void
    {
        $_SESSION = ['user_id' => 1, 'username' => 'user@example.org', 'password' => $this->rcmail->encrypt('credential')];
        $client = $this->client(new FakeResponse(204));

        $this->plugin->startup(['task' => 'logout', 'action' => '']);

        $this->assertSame('https://users.example.org/api/roundcube/logout', $client->calls[0]['url']);
        $this->assertSame(['email' => 'user@example.org', 'password' => 'credential'], $client->calls[0]['json']);
    }

    public function testLogoutWithoutValidTokenDoesNotRevoke(): void
    {
        $_SESSION = ['user_id' => 1, 'username' => 'user@example.org', 'password' => $this->rcmail->encrypt('credential')];
        $this->rcmail->requestValid = false;
        $client = $this->client();

        $this->plugin->startup(['task' => 'logout', 'action' => '']);

        $this->assertSame([], $client->calls);
    }

    public function testSessionEndsWhenCredentialExpired(): void
    {
        $_SESSION = ['user_id' => 1, 'userli_expires' => time() - 1];

        $this->plugin->startup(['task' => 'mail', 'action' => '']);

        $this->assertTrue($this->rcmail->sessionKilled);
    }

    public function testSessionContinuesBeforeCredentialExpired(): void
    {
        $_SESSION = ['user_id' => 1, 'userli_expires' => time() + 60];

        $this->plugin->startup(['task' => 'mail', 'action' => '']);

        $this->assertFalse($this->rcmail->sessionKilled);
    }
}
