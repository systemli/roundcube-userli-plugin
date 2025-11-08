<?php

/**
 * PHPUnit bootstrap file for userli plugin tests
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Mock Roundcube classes for testing
if (!class_exists('rcube_plugin')) {
    class rcube_plugin
    {
        public $task;
        private $hooks = [];

        protected function add_hook($hook, $callback)
        {
            $this->hooks[$hook] = $callback;
        }

        protected function load_config()
        {
            // Mock implementation
        }

        public function getHooks()
        {
            return $this->hooks;
        }
    }
}

if (!class_exists('rcmail')) {
    class rcmail
    {
        private static $instance;
        public $user;
        public $config;
        private $httpClient;

        public static function get_instance()
        {
            if (!self::$instance) {
                self::$instance = new self();
            }
            return self::$instance;
        }

        public function get_http_client()
        {
            return $this->httpClient;
        }

        public function set_http_client($client)
        {
            $this->httpClient = $client;
        }
    }
}

if (!class_exists('rcube')) {
    class rcube
    {
        public static function raise_error($args, $log = false, $fatal = false)
        {
            // Mock implementation - do nothing in tests
        }
    }
}
