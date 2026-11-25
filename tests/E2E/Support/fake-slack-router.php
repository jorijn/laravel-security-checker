<?php

/**
 * Router script for PHP's built-in web server that plays the receiving end of every webhook:
 * Slack, Teams (Workflows) and the generic webhook.
 *
 * Every request is appended to the file named by FAKE_SLACK_LOG, so tests can assert on the
 * exact JSON payload the package POSTed. Slack itself answers "ok" with a 200, so we do too.
 * A path ending in /status/<code> answers with that HTTP status instead, to simulate a
 * receiver that rejects the request.
 */

$entry = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
    'body' => file_get_contents('php://input'),
    'signature' => $_SERVER['HTTP_X_SIGNATURE_256'] ?? null,
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
];

file_put_contents((string) getenv('FAKE_SLACK_LOG'), json_encode($entry)."\n", FILE_APPEND | LOCK_EX);

header('Content-Type: text/plain');

if (preg_match('#/status/(\d{3})$#', $entry['uri'], $m)) {
    http_response_code((int) $m[1]);
    echo 'rejected by the fake receiver';

    return;
}

echo 'ok';
