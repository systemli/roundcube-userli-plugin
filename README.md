# Roundcube Userli Plugin

A Roundcube plugin for [Userli](https://github.com/systemli/userli):

* **Login with two-factor authentication:** the plugin checks the password and, for users with 2FA, asks for the TOTP or backup code in a second step. Userli then issues a webmail credential, which Roundcube uses for IMAP and SMTP instead of the password. It is valid for 12 hours; the Roundcube session ends with it. Logging out revokes it.
* **Alias identities:** at login, the plugin creates a Roundcube identity for each alias of the user.

With a Userli version without the webmail login endpoint, the plugin keeps logging in with the password.

## Installation

1. Clone this repository into your Roundcube plugins directory
2. Copy `config.inc.php.dist` to `config.inc.php` and configure your API settings
3. Enable the plugin in your Roundcube configuration

## Configuration

Edit `config.inc.php` with your userli API settings:

```php
$config['userli_url'] = 'https://your-api.example.org';
$config['userli_token'] = 'your-api-token';
$config['userli_ssl_verify'] = true;
```

## Testing

This plugin includes a comprehensive unit test suite. To run the tests:

```bash
# Install dependencies
composer install

# Run tests
composer test

# Or run PHPUnit directly
./vendor/bin/phpunit

# Run tests with verbose output
./vendor/bin/phpunit --verbose
```
