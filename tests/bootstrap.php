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
        public $api;
        private $hooks = [];

        public function __construct()
        {
            $this->api = new stdClass();
            $this->api->output = new class {
                public function add_script($script)
                {
                }
            };
        }

        protected function add_texts($dir)
        {
        }

        public function gettext($name)
        {
            return $name;
        }

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
        public $requestValid = true;
        public $sessionKilled = false;
        private $httpClient;

        public function encrypt($clear)
        {
            return 'encrypted:' . base64_encode($clear);
        }

        public function decrypt($cipher)
        {
            return base64_decode(substr($cipher, strlen('encrypted:')));
        }

        public function check_request($mode)
        {
            return $this->requestValid;
        }

        public function get_user_name()
        {
            return $_SESSION['username'] ?? null;
        }

        public function get_user_password()
        {
            return isset($_SESSION['password']) ? $this->decrypt($_SESSION['password']) : null;
        }

        public function kill_session()
        {
            $this->sessionKilled = true;
            $_SESSION = [];
        }

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

if (!class_exists('rcube_utils')) {
    class rcube_utils
    {
        public const INPUT_GET = 1;
        public const INPUT_POST = 2;

        public static function get_input_string($name, $source)
        {
            return $_POST[$name] ?? '';
        }
    }
}

if (!class_exists('html')) {
    class html
    {
        public static function label($for, $text)
        {
            return '<label for="' . $for . '">' . $text . '</label>';
        }

        public static function quote($str)
        {
            return htmlspecialchars((string) $str);
        }
    }

    class html_inputfield
    {
        public function __construct(private array $attrib = [])
        {
        }

        public function show()
        {
            $attrs = '';
            foreach ($this->attrib as $key => $value) {
                $attrs .= ' ' . $key . '="' . htmlspecialchars((string) $value) . '"';
            }
            return '<input' . $attrs . '>';
        }
    }

    class html_hiddenfield extends html_inputfield
    {
    }
}
