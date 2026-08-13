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

        if ((static::$config['secret'] ?? null) === null) {
            if ($envSecret = static::envValue('X_CSRF_SECRET')) {
                static::config(['secret' => $envSecret]);
            } elseif ($appKey = static::envValue('APP_KEY')) {
                static::config(['secret' => hash_hmac('sha256', 'leaf.csrf.secret.v1', $appKey)]);
            } else {
                throw new \RuntimeException(
                    'No CSRF secret is set. Generate an APP_KEY with `php leaf key:generate`, set X_CSRF_SECRET in your .env, or pass a `secret` to csrf().'
                );
            }
        }

        if (!isset($_SESSION[static::$config['secretKey']])) {
            Session::set(static::$config['secretKey'], static::generateToken());
        }

        static::setClientCookie();
    }

    /**
     * Read an environment value, with or without leaf core around.
     * Reads live rather than through _env()'s per-process cache: secret
     * resolution runs once per init(), so the uncached read costs nothing
     * and stays honest when the environment is set at runtime.
     * @return mixed
     */
    protected static function envValue(string $key)
    {
        if (function_exists('_envUncached')) {
            return _envUncached($key);
        }

        $value = $_ENV[$key] ?? getenv($key);

        return ($value === false || $value === '') ? null : $value;
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
                \Leaf\Crash\Pages::csrf(static::$errors['token']);
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
