<?php

namespace Jorijn\LaravelSecurityChecker\Advisories;

use Illuminate\Http\Client\PendingRequest;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;

/**
 * Downloads every advisory Packagist knows about and leaves the matching to the caller.
 *
 * This is the default because it is private: the request is identical for every app, so the
 * list of packages (and versions) an application uses never leaves the server. The price is
 * the download size: about 4 MB of JSON, roughly 0.7 MB on the wire because it is gzipped.
 *
 * The full feed was compared with per-package results for 163 packages before it became the
 * default (no differences), and the nightly CI job keeps comparing them.
 */
class PackagistFullFeed extends PackagistApi
{
    public function advisoriesFor(array $packageNames): array
    {
        // `updatedSince=0` asks for everything. It is required: without it (and without a
        // package list) the API answers HTTP 400.
        $response = $this->send(
            fn (PendingRequest $request) => $request->get('/api/security-advisories/', ['updatedSince' => 0]),
            'the security advisories feed'
        );

        $advisories = $this->advisoriesFrom($response, 'the security advisories feed');

        // packagist.org lists thousands of advisories. An empty feed means something is broken
        // on the way (a captive portal, a misconfigured mirror) and must not read as "all clear".
        if ($advisories === []) {
            throw CheckFailedException::because(
                'The security advisories feed from Packagist was empty, which is not plausible.'
            );
        }

        return $advisories;
    }
}
