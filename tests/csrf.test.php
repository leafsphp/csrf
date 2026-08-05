<?php

declare(strict_types=1);

use Leaf\Anchor\CSRF;

beforeEach(function () {
    resetCsrfState();
});

// ---- init / token / form ----

test('init stores a token in the session under the secret key', function () {
    $_SERVER['REQUEST_METHOD'] = 'GET';

    CSRF::init();

    expect($_SESSION)->toHaveKey(csrfSecretKey());
    expect($_SESSION[csrfSecretKey()])->toBeString()->not()->toBe('');
});

test('init does not regenerate an existing token', function () {
    $_SERVER['REQUEST_METHOD'] = 'GET';

    CSRF::init();
    $first = $_SESSION[csrfSecretKey()];

    CSRF::init();

    expect($_SESSION[csrfSecretKey()])->toBe($first);
});

test('token returns the session token', function () {
    $_SESSION[csrfSecretKey()] = 'my-test-token';

    expect(CSRF::token())->toBe('my-test-token');
});

test('form echoes a hidden input with escaped name and value', function () {
    $_SESSION[csrfSecretKey()] = 'tok"en<script>';

    ob_start();
    CSRF::form();
    $output = ob_get_clean();

    expect($output)->toContain('<input type="hidden"');
    expect($output)->toContain('name="' . csrfSecretKey() . '"');
    expect($output)->toContain('value="tok&quot;en&lt;script&gt;"');
    expect($output)->not()->toContain('value="tok"en');
});

// ---- verify: method gating ----

test('verify returns true for methods outside the configured list', function () {
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['REQUEST_URI'] = '/some/path';

    expect(CSRF::verify())->toBeTrue();
});

// ---- verify: token checks ----

test('verify fails a POST with no token and records tokenNotFound', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SESSION[csrfSecretKey()] = 'session-token';

    expect(CSRF::verify())->toBeFalse();
    expect(CSRF::errors())->toHaveKey('token');
    expect(CSRF::errors()['token'])->toBe(CSRF::config()['messages.tokenNotFound']);
});

test('verify fails a POST with a wrong token and records tokenInvalid', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SESSION[csrfSecretKey()] = 'session-token';
    $_POST[csrfSecretKey()] = 'wrong-token';

    expect(CSRF::verify())->toBeFalse();
    expect(CSRF::errors()['token'])->toBe(CSRF::config()['messages.tokenInvalid']);
});

test('verify passes a POST with the correct token in the body', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SESSION[csrfSecretKey()] = 'session-token';
    $_POST[csrfSecretKey()] = 'session-token';

    expect(CSRF::verify())->toBeTrue();
});

test('verify passes a POST with the correct token in the X-CSRF-TOKEN header', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SESSION[csrfSecretKey()] = 'session-token';
    $_SERVER['HTTP_X_CSRF_TOKEN'] = 'session-token';

    expect(CSRF::verify())->toBeTrue();
});

test('verify fails without a TypeError when the request token is an array', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SESSION[csrfSecretKey()] = 'session-token';
    $_POST[csrfSecretKey()] = ['session-token'];

    expect(CSRF::verify())->toBeFalse();
    expect(CSRF::errors()['token'])->toBe(CSRF::config()['messages.tokenInvalid']);
});

// ---- verify: exceptions ----

test('verify skips literal excepted paths without a token', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/no-csrf';
    $_SESSION[csrfSecretKey()] = 'session-token';

    CSRF::config(['except' => ['/no-csrf']]);

    expect(CSRF::verify())->toBeTrue();
});

test('verify skips dynamic excepted patterns without a token', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/webhooks/stripe';
    $_SESSION[csrfSecretKey()] = 'session-token';

    CSRF::config(['except' => ['/webhooks/{service}']]);

    expect(CSRF::verify())->toBeTrue();
});

test('verify still verifies paths not matched by a dynamic pattern', function () {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/webhooks';
    $_SESSION[csrfSecretKey()] = 'session-token';

    CSRF::config(['except' => ['/webhooks/{service}']]);

    expect(CSRF::verify())->toBeFalse();
    expect(CSRF::errors())->toHaveKey('token');
});

// ---- rotation flows ----

test('default flow: token survives a successful verify (per-session token)', function () {
    \Leaf\Anchor\CSRF::init();
    $token = \Leaf\Anchor\CSRF::token();

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_POST[csrfSecretKey()] = $token;

    expect(\Leaf\Anchor\CSRF::verify())->toBeTrue();
    expect(\Leaf\Anchor\CSRF::token())->toBe($token);

    // and the same token keeps working on the next request
    expect(\Leaf\Anchor\CSRF::verify())->toBeTrue();
});

test('rotate flow: a token is only good for one request', function () {
    \Leaf\Anchor\CSRF::config(['rotate' => true]);
    \Leaf\Anchor\CSRF::init();
    $firstToken = \Leaf\Anchor\CSRF::token();

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_POST[csrfSecretKey()] = $firstToken;

    expect(\Leaf\Anchor\CSRF::verify())->toBeTrue();

    $secondToken = \Leaf\Anchor\CSRF::token();
    expect($secondToken)->not()->toBe($firstToken);

    // replaying the first token now fails
    expect(\Leaf\Anchor\CSRF::verify())->toBeFalse();

    // the fresh token passes
    $_POST[csrfSecretKey()] = $secondToken;
    expect(\Leaf\Anchor\CSRF::verify())->toBeTrue();
    expect(\Leaf\Anchor\CSRF::token())->not()->toBe($secondToken);
});

test('regenerate issues a fresh token for manual rotation (e.g. on login)', function () {
    \Leaf\Anchor\CSRF::init();
    $before = \Leaf\Anchor\CSRF::token();

    $issued = \Leaf\Anchor\CSRF::regenerate();

    expect($issued)->not()->toBe($before);
    expect(\Leaf\Anchor\CSRF::token())->toBe($issued);
});

// ---- SPA header flow ----

test('verify accepts the token via the X-XSRF-TOKEN header', function () {
    \Leaf\Anchor\CSRF::init();

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SERVER['HTTP_X_XSRF_TOKEN'] = \Leaf\Anchor\CSRF::token();

    expect(\Leaf\Anchor\CSRF::verify())->toBeTrue();
});

test('verify rejects a wrong token via the X-XSRF-TOKEN header', function () {
    \Leaf\Anchor\CSRF::init();

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REQUEST_URI'] = '/submit';
    $_SERVER['HTTP_X_XSRF_TOKEN'] = 'wrong-token';

    expect(\Leaf\Anchor\CSRF::verify())->toBeFalse();
});
