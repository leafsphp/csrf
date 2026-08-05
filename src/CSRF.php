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

        static::setClientCookie();
    }

    /**
     * Issue a fresh token, replacing the current one.
     * Call this on login, or let the `rotate` config do it per request.
     * @return string The new token
     */
    public static function regenerate(): string
    {
        $token = static::generateToken();

        Session::set(static::$config['secretKey'], $token);
        static::setClientCookie();

        return $token;
    }

    /**
     * Drop the token in a JS-readable XSRF-TOKEN cookie so SPA clients
     * (axios, inertia, fetch wrappers) can echo it back as X-XSRF-TOKEN
     * without any hand-plumbing. Disable with config ['cookie' => false].
     */
    protected static function setClientCookie(): void
    {
        if ((static::$config['cookie'] ?? true) === false || headers_sent()) {
            return;
        }

        setcookie('XSRF-TOKEN', static::token() ?? '', [
            'expires' => 0,
            'path' => '/',
            'secure' => ($_SERVER['HTTPS'] ?? '') !== '',
            'httponly' => false, // JS must be able to read it to echo it back
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Validate the CSRF token
     * @return bool
     */
    public static function verify(): bool
    {
        $except = static::$config['except'] ?? [];
        $currentPath = Request::getPathInfo();

        if (in_array($currentPath, $except)) {
            return true;
        }

        if (
            class_exists('Leaf\App') &&
            in_array(
                app()->findRoute()[0]['route']['pattern'] ?? $currentPath,
                array_map(function ($item) {
                    return preg_replace('/\/{(.*?)}/', '/(.*?)', $item);
                }, $except)
            )
        ) {
            return true;
        }

        // dynamic exceptions like /webhooks/{service} should also match
        // the raw request path when no router is around to resolve it
        foreach ($except as $exceptPattern) {
            if (strpos($exceptPattern, '{') === false) {
                continue;
            }

            $exceptRegex = '#^' . preg_replace('/\/{(.*?)}/', '/[^/]+', $exceptPattern) . '$#';

            if (preg_match($exceptRegex, $currentPath) === 1) {
                return true;
            }
        }

        if (in_array(Request::getMethod(), static::$config['methods'])) {
            $requestData = Request::body();
            $requestHeaders = Request::headers();

            $requestToken = $requestData[static::$config['secretKey']]
                ?? $requestHeaders[static::$config['secretKey']]
                ?? $requestHeaders['x-csrf-token']
                ?? $requestHeaders['X-CSRF-TOKEN']
                ?? $requestHeaders['X-CSRF-Token']
                ?? $requestHeaders['X-Csrf-Token']
                // SPA clients (axios and friends) echo the XSRF-TOKEN
                // cookie back as an X-XSRF-TOKEN header automatically
                ?? $requestHeaders['x-xsrf-token']
                ?? $requestHeaders['X-XSRF-TOKEN']
                ?? $requestHeaders['X-XSRF-Token']
                ?? $requestHeaders['X-Xsrf-Token']
                ?? null;

            if (!$requestToken) {
                static::$errors['token'] = static::$config['messages.tokenNotFound'];

                return false;
            }

            $sessionToken = $_SESSION[static::$config['secretKey']] ?? null;

            if (!is_string($sessionToken) || !is_string($requestToken) || !hash_equals($sessionToken, $requestToken)) {
                static::$errors['token'] = static::$config['messages.tokenInvalid'];

                return false;
            }

            // opt-in rotation: a token is only good for one request. The
            // per-session default stays friendlier to multi-tab apps.
            if (static::$config['rotate'] ?? false) {
                static::regenerate();
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
        echo '<input type="hidden" name="' . htmlspecialchars(static::$config['secretKey'], ENT_QUOTES, 'UTF-8') . '" value="' . htmlspecialchars(static::token() ?? '', ENT_QUOTES, 'UTF-8') . '" />';
    }
}
