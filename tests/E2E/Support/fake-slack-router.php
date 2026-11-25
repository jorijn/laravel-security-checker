<?php

/**
 * Router script for PHP's built-in web server that plays the Slack incoming webhook.
 *
 * Every request is appended to the file named by FAKE_SLACK_LOG, so tests can assert on the
 * exact JSON payload the package POSTed. Slack itself answers "ok" with a 200, so we do too.
 */

$entry = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
    'body' => file_get_contents('php://input'),
];

file_put_contents((string) getenv('FAKE_SLACK_LOG'), json_encode($entry)."\n", FILE_APPEND | LOCK_EX);

header('Content-Type: text/plain');
echo 'ok';
