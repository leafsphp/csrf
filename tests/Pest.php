<?php

declare(strict_types=1);

// Start the session once, before any test output, so CSRF::init() and
// Session::set() never attempt session_start() mid-run.
ini_set('session.use_cookies', '0');
ini_set('session.cache_limiter', '');
@session_start();

function csrfSecretKey(): string
{
    return \Leaf\Anchor\CSRF::config()['secretKey'];
}

function resetCsrfState(): void
{
    $_SESSION = [];
    $_POST = [];
    $_GET = [];

    unset(
        $_SERVER['REQUEST_METHOD'],
        $_SERVER['REQUEST_URI'],
        $_SERVER['HTTP_X_CSRF_TOKEN'],
        $_SERVER['HTTP_X_XSRF_TOKEN'],
        $_SERVER['HTTP_X_LEAF_CSRF_TOKEN']
    );

    \Leaf\Anchor\CSRF::config([
        'secret' => 'test-secret',
        'except' => [],
        'methods' => ['POST', 'PUT', 'PATCH', 'DELETE'],
        'rotate' => false,
        'cookie' => true,
    ]);

    $errors = new ReflectionProperty(\Leaf\Anchor\CSRF::class, 'errors');
    $errors->setAccessible(true);
    $errors->setValue(null, []);
}
