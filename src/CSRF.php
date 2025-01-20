<?php

declare(strict_types=1);

namespace Leaf\Anchor;

use Leaf\Anchor;
use Leaf\Http\Request;
use Leaf\Http\Session;

/**
 * Leaf CSRF Module
 * ----------------
 * Add CSRF protection to your app
 * 
 * @since 3.0.0
 */
class CSRF extends Anchor
{
    public static function init()
    {        
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        if (!isset($_SESSION[static::$config['secretKey']])) {
            Session::set(static::$config['secretKey'], static::generateToken());
        }
    }

    public static function getPathExpression($url): mixed
    {
        foreach (static::$config['except'] as $pattern) {
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

    /**
     * Validate the CSRF token
     * @return bool
     */
    public static function verify(): bool
    {
        // verify routes with explicit definition
        if (class_exists('Leaf\App')) {
            if (
                in_array(
                    app()->findRoute()[0]['route']['pattern'] ?? Request::getPathInfo(),
                    array_map(function ($item) {
                        return preg_replace('/\/{(.*?)}/', '/(.*?)', $item);
                    }, static::$config['except'])
                )
            ) { return true; }
        } else {
            if (in_array(Request::getPathInfo(), static::$config['except'])) {
                return true;
            }
        }
        
        // verify routes with pattern definitions
        $pattern = static::getPathExpression(Request::getPathInfo());
        if (!is_null($pattern) and in_array($pattern, static::$config['except'])) {
            return true;
        }

        if (in_array(Request::getMethod(), static::$config['methods'])) {
            $requestData = Request::body();
            $requestHeaders = Request::headers();

            # TODO: check for csrf token in headers using regex matching the csrf token header pattern
            $requestToken = $requestData[static::$config['secretKey']]
                ?? $requestHeaders[static::$config['secretKey']]
                ?? $requestHeaders['x-csrf-token']
                ?? $requestHeaders['X-CSRF-TOKEN']
                ?? $requestHeaders['X-CSRF-Token']
                ?? $requestHeaders['X-Csrf-Token']
                ?? null;

            if (!$requestToken) {
                static::$errors['token'] = static::$config['messages.tokenNotFound'];
                return false;
            }

            $sessionToken = $_SESSION[static::$config['secretKey']] ?? null;

            if ($requestToken !== $sessionToken) {
                static::$errors['token'] = static::$config['messages.tokenInvalid'];
                return false;
            }
        }

        return true;
    }

    /**
     * Validate the CSRF token and run associated handler
     */
    public static function validate()
    {
        if (!static::verify()) {
            if (static::$config['onError']) {
                static::$config['onError'](
                    static::$errors['token'] === static::$config['messages.tokenNotFound']
                    ? 'tokenNotFound' : 'tokenInvalid'
                );
                exit(); // failsafe to prevent further execution
            } else {
                response()->exit(
                    \Leaf\Exception\General::csrf(static::$errors['token']),
                    400
                );
            }
        }
    }

    public static function token()
    {
        return $_SESSION[static::$config['secretKey']] ?? null;
    }

    public static function form()
    {
        echo '<input type="hidden" name="' . static::$config['secretKey'] . '" value="' . (static::token() ?? '') . '" />';
    }
}
