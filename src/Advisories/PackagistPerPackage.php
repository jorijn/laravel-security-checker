<?php

namespace Jorijn\LaravelSecurityChecker\Advisories;

use Illuminate\Http\Client\PendingRequest;

/**
 * Asks Packagist for the advisories of the installed packages only.
 *
 * Much smaller downloads than the full feed, but Packagist learns which packages the
 * application uses, including the names of private packages. Opt-in for that reason.
 */
class PackagistPerPackage extends PackagistApi
{
    /**
     * A lock file easily lists a few hundred packages: POST keeps them out of the URL, and
     * batches keep each request well within server limits. Composer itself sends one batch;
     * smaller batches cost a few extra requests but never hit a request size limit.
     */
    public const BATCH_SIZE = 100;

    public function advisoriesFor(array $packageNames): array
    {
        $advisories = [];

        foreach (array_chunk(array_values(array_unique($packageNames)), self::BATCH_SIZE) as $batch) {
            $what = 'security advisories for '.count($batch).' packages';
            $response = $this->send(
                fn (PendingRequest $request) => $request->asForm()
                    ->post('/api/security-advisories/', ['packages' => $batch]),
                $what
            );

            $advisories += $this->advisoriesFrom($response, $what);
        }

        return $advisories;
    }
}
