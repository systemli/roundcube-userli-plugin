<?php

/**
 * Unit tests for userli plugin
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../userli.php';

class UserliAliasesTest extends TestCase
{
    private $plugin;
    private $rcmail;
    private $mockUser;
    private $mockConfig;

    protected function setUp(): void
    {
        $this->plugin = new userli();
        $this->rcmail = rcmail::get_instance();
        
        // Create mock user using getMockBuilder
        $this->mockUser = $this->getMockBuilder(stdClass::class)
            ->addMethods(['get_username', 'list_emails', 'delete_identity', 'insert_identity'])
            ->getMock();
        $this->mockUser->ID = 1;
        $this->mockUser->method('get_username')->willReturn('user@example.org');
        
        // Create mock config using getMockBuilder
        $this->mockConfig = $this->getMockBuilder(stdClass::class)
            ->addMethods(['get'])
            ->getMock();
        
        $this->rcmail->user = $this->mockUser;
        $this->rcmail->config = $this->mockConfig;
    }

    public function testInitRegistersHooks(): void
    {
        $this->plugin->init();
        $hooks = $this->plugin->getHooks();
        
        $this->assertArrayHasKey('authenticate', $hooks);
        $this->assertArrayHasKey('login_after', $hooks);
    }

    public function testAuthenticateStoresPassword(): void
    {
        $args = ['pass' => 'test_password_123'];
        
        $this->plugin->authenticate_store_pass($args);
        
        // We can't directly test the private property, but we can verify no errors occur
        $this->assertTrue(true);
    }

    public function testLoginAfterWithSuccessfulApiResponse(): void
    {
        // Mock configuration
        $this->mockConfig->method('get')->willReturnCallback(function ($key) {
            $config = [
                'userli_url' => 'https://api.example.org',
                'userli_ssl_verify' => true,
                'userli_token' => 'test-token',
            ];
            return $config[$key] ?? null;
        });

        // Mock HTTP response
        $mockResponse = $this->getMockBuilder(stdClass::class)
            ->addMethods(['getStatusCode', 'getBody'])
            ->getMock();
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn(json_encode([
            'alias1@example.org',
            'alias2@example.org',
        ]));

        // Mock HTTP client
        $mockClient = $this->getMockBuilder(stdClass::class)
            ->addMethods(['request'])
            ->getMock();
        $mockClient->method('request')->willReturn($mockResponse);
        
        $this->rcmail->set_http_client($mockClient);

        // Mock user identities
        $this->mockUser->method('list_emails')->willReturn([
            ['identity_id' => 1, 'email' => 'user@example.org'],
        ]);
        
        $this->mockUser->expects($this->exactly(2))
            ->method('insert_identity')
            ->withConsecutive(
                [$this->callback(function ($data) {
                    return $data['email'] === 'alias1@example.org';
                })],
                [$this->callback(function ($data) {
                    return $data['email'] === 'alias2@example.org';
                })]
            );

        $this->plugin->login_after_update_identities();
    }

    public function testLoginAfterHandlesNon200Response(): void
    {
        // Mock configuration
        $this->mockConfig->method('get')->willReturnCallback(function ($key) {
            $config = [
                'userli_url' => 'https://api.example.org',
                'userli_ssl_verify' => true,
                'userli_token' => 'test-token',
            ];
            return $config[$key] ?? null;
        });

        // Mock HTTP response with error code
        $mockResponse = $this->getMockBuilder(stdClass::class)
            ->addMethods(['getStatusCode', 'getBody'])
            ->getMock();
        $mockResponse->method('getStatusCode')->willReturn(401);
        $mockResponse->method('getBody')->willReturn('Unauthorized');

        // Mock HTTP client
        $mockClient = $this->getMockBuilder(stdClass::class)
            ->addMethods(['request'])
            ->getMock();
        $mockClient->method('request')->willReturn($mockResponse);
        
        $this->rcmail->set_http_client($mockClient);

        // Should not throw exception, but handle gracefully
        $this->plugin->login_after_update_identities();
        
        // Test passes if no exception is thrown
        $this->assertTrue(true);
    }

    public function testLoginAfterHandlesInvalidJsonResponse(): void
    {
        // Mock configuration
        $this->mockConfig->method('get')->willReturnCallback(function ($key) {
            $config = [
                'userli_url' => 'https://api.example.org',
                'userli_ssl_verify' => true,
                'userli_token' => 'test-token',
            ];
            return $config[$key] ?? null;
        });

        // Mock HTTP response with invalid JSON
        $mockResponse = $this->getMockBuilder(stdClass::class)
            ->addMethods(['getStatusCode', 'getBody'])
            ->getMock();
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn('not valid json{');

        // Mock HTTP client
        $mockClient = $this->getMockBuilder(stdClass::class)
            ->addMethods(['request'])
            ->getMock();
        $mockClient->method('request')->willReturn($mockResponse);
        
        $this->rcmail->set_http_client($mockClient);

        // Should handle gracefully
        $this->plugin->login_after_update_identities();
        
        $this->assertTrue(true);
    }

    public function testLoginAfterHandlesHttpException(): void
    {
        // Mock configuration
        $this->mockConfig->method('get')->willReturnCallback(function ($key) {
            $config = [
                'userli_url' => 'https://api.example.org',
                'userli_ssl_verify' => true,
                'userli_token' => 'test-token',
            ];
            return $config[$key] ?? null;
        });

        // Mock HTTP client that throws exception
        $mockClient = $this->getMockBuilder(stdClass::class)
            ->addMethods(['request'])
            ->getMock();
        $mockClient->method('request')->willThrowException(new Exception('Network error'));
        
        $this->rcmail->set_http_client($mockClient);

        // Should handle exception gracefully
        $this->plugin->login_after_update_identities();
        
        $this->assertTrue(true);
    }

    public function testLoginAfterRemovesOldAliases(): void
    {
        // Mock configuration
        $this->mockConfig->method('get')->willReturnCallback(function ($key) {
            $config = [
                'userli_url' => 'https://api.example.org',
                'userli_ssl_verify' => true,
                'userli_token' => 'test-token',
            ];
            return $config[$key] ?? null;
        });

        // Mock HTTP response with only one alias
        $mockResponse = $this->getMockBuilder(stdClass::class)
            ->addMethods(['getStatusCode', 'getBody'])
            ->getMock();
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn(json_encode([
            'alias1@example.org',
        ]));

        // Mock HTTP client
        $mockClient = $this->getMockBuilder(stdClass::class)
            ->addMethods(['request'])
            ->getMock();
        $mockClient->method('request')->willReturn($mockResponse);
        
        $this->rcmail->set_http_client($mockClient);

        // Mock user identities with old alias that should be removed
        $this->mockUser->method('list_emails')->willReturn([
            ['identity_id' => 1, 'email' => 'user@example.org'],
            ['identity_id' => 2, 'email' => 'alias1@example.org'],
            ['identity_id' => 3, 'email' => 'old_alias@example.org'],
        ]);
        
        // Should delete the old alias
        $this->mockUser->expects($this->once())
            ->method('delete_identity')
            ->with(3);

        // Should not insert alias1 as it already exists
        $this->mockUser->expects($this->never())
            ->method('insert_identity');

        $this->plugin->login_after_update_identities();
    }

    public function testLoginAfterPreservesMainUserIdentity(): void
    {
        // Mock configuration
        $this->mockConfig->method('get')->willReturnCallback(function ($key) {
            $config = [
                'userli_url' => 'https://api.example.org',
                'userli_ssl_verify' => true,
                'userli_token' => 'test-token',
            ];
            return $config[$key] ?? null;
        });

        // Mock HTTP response with empty aliases
        $mockResponse = $this->getMockBuilder(stdClass::class)
            ->addMethods(['getStatusCode', 'getBody'])
            ->getMock();
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn(json_encode([]));

        // Mock HTTP client
        $mockClient = $this->getMockBuilder(stdClass::class)
            ->addMethods(['request'])
            ->getMock();
        $mockClient->method('request')->willReturn($mockResponse);
        
        $this->rcmail->set_http_client($mockClient);

        // Mock user identities - only main identity
        $this->mockUser->method('list_emails')->willReturn([
            ['identity_id' => 1, 'email' => 'user@example.org'],
        ]);
        
        // Main identity should never be deleted
        $this->mockUser->expects($this->never())
            ->method('delete_identity');

        $this->plugin->login_after_update_identities();
    }
}
