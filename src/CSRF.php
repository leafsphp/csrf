<?php

declare(strict_types=1);

namespace Leaf\Anchor;

use Leaf\Anchor;
use Leaf\Http\Request;
use Leaf\Http\Session;

/**
 * CSRF handler
 */
class CSRF extends Anchor
{
    const TOKEN_NOT_FOUND = 'Token not found.';
    const TOKEN_INVALID = 'Invalid token.';

    /**
     * Manage config for leaf anchor
     *
     * @param array|null $config The config to set
     */
    public static function config($config = null)
    {
        if (file_exists('config/csrf.php')) {
            static::$config = require 'config/csrf.php';
        }
        
        if ($config === null) {
            return static::$config;
        }

        static::$config = array_merge(static::$config, $config);
    }

    public static function init()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        if (!isset($_SESSION[static::$config["SECRET_KEY"]])) {
            Session::set(static::$config["SECRET_KEY"], static::generateToken());
        }
    }

    public static function getPathExpression($url): mixed
    {
        foreach (static::$config['EXCEPT'] as $pattern) {
            $regex = '#^' . strtr(preg_quote($pattern, '#'), [
                '\{int\}' => '(\d+)',           # number based values
                '\{slug\}' => '([a-z0-9-]+)',   # alpha numerical values
                '\{any\}' => '([^/]+?)',        # anything except slashes
                '\{wild\}' => '(.*)'            # wild card
            ]) . '$#i';

            if (preg_match($regex, $url, $matches)) {
                return $pattern;
            }
        }

        return null;
    }

  public static function verify(): bool
    {
        // Check if the request path is in the exceptions list
        if (in_array(Request::getPathInfo(), static::$config['EXCEPT'])) {
            return true;
        }

        // Check if the request method is in the allowed methods list
        if (in_array(Request::getMethod(), static::$config["METHODS"])) {
            // Get request data and headers
            $requestData = Request::body();
            $requestHead = Request::headers();
            //print_r($requestHead);

            // Retrieve the token from request body, headers, or the X-CSRF-TOKEN header
            $requestToken = $requestData[static::$config["SECRET_KEY"]]
                ?? $requestHead[static::$config["SECRET_KEY"]]
                ?? $requestHead['x-csrf-token']
                ?? null;

            // Check if the request token (either from SECRET_KEY or X-CSRF-TOKEN) is present
            if (!$requestToken) {
                static::$errors["token"] = static::TOKEN_NOT_FOUND;
                return false;
            }

            // Validate the token against the session
            $sessionToken = $_SESSION[static::$config["SECRET_KEY"]] ?? null;

            if ($requestToken !== $sessionToken) {
                static::$errors["token"] = static::TOKEN_INVALID;
                return false;
            }
        }

    public static function token()
    {
        return ($_SESSION[static::$config["SECRET_KEY"]] ?? null) ? [static::$config["SECRET_KEY"] => $_SESSION[static::$config["SECRET_KEY"]]] : null;
    }

    public static function form()
    {
        echo '<input type="hidden" name="' . static::$config["SECRET_KEY"] . '" value="' . $_SESSION[static::$config["SECRET_KEY"]] . '" />';
    }
}
