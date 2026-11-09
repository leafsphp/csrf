<?php

function runCsrfValidate(string $mode = ''): array
{
    $cmd = implode(' ', array_filter([
        escapeshellarg(PHP_BINARY),
        escapeshellarg(__DIR__ . '/fixtures/validate.php'),
        escapeshellarg(dirname(__DIR__) . '/vendor/autoload.php'),
        $mode ? escapeshellarg($mode) : null,
    ]));

    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    return [$out, $err];
}

test('validate renders the Crash csrf page when leafs/exception v5 is present', function () {
    if (!class_exists(\Leaf\Crash\Pages::class)) {
        $this->markTestSkipped('leafs/exception v5 not installed');
    }

    [$out, $err] = runCsrfValidate();

    expect($out)->toContain('Invalid request');
    expect($out)->toContain('<html');
    expect($out)->not->toContain('NOT-STOPPED');
    expect($err)->toContain('STATUS=400');
});

test('validate falls back to a plain 400 when Crash\Pages is unavailable (Leaf 4)', function () {
    [$out, $err] = runCsrfValidate('no-pages');

    expect($out)->toContain(\Leaf\Anchor\CSRF::config()['messages.tokenNotFound'] ?? 'Token not found.');
    expect($out)->not->toContain('<html');
    expect($out)->not->toContain('NOT-STOPPED');
    expect($err)->toContain('STATUS=400');
});
