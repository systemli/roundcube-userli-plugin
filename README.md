# Roundcube Userli Aliases

A Roundcube plugin that automatically synchronizes user identities from a userli aliases API at login.

## Installation

1. Clone this repository into your Roundcube plugins directory
2. Copy `config.inc.php.dist` to `config.inc.php` and configure your API settings
3. Enable the plugin in your Roundcube configuration

## Configuration

Edit `config.inc.php` with your userli API settings:

```php
$config['userli_aliases_url'] = 'https://your-api.example.org/api/roundcube/aliases';
$config['userli_aliases_token'] = 'your-api-token';
$config['userli_aliases_ssl_verify'] = true;
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
