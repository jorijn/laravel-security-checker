<?php

namespace Jorijn\LaravelSecurityChecker\Checkers;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\MatchAllConstraint;
use Composer\Semver\VersionParser;
use Jorijn\LaravelSecurityChecker\Contracts\AdvisorySource;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\LockFile;
use Jorijn\LaravelSecurityChecker\Severity;
use UnexpectedValueException;

/**
 * Checks composer.lock against Packagist's security advisories, matching versions locally.
 *
 * The matching follows `composer audit` (composer/composer's PartialSecurityAdvisory and
 * Auditor), so both tools report the same vulnerabilities for the same lock file.
 */
class PackagistChecker implements Checker
{
    private readonly VersionParser $versionParser;

    /**
     * @var array<string, ConstraintInterface>
     */
    private array $constraints = [];

    public function __construct(private readonly AdvisorySource $source)
    {
        $this->versionParser = new VersionParser();
    }

    public function check(string $composerLock, bool $excludeDev = false, array $allowList = []): array
    {
        $lockFile = LockFile::read($composerLock);
        $installed = $lockFile->packages($excludeDev);

        if ($installed === []) {
            return [];
        }

        $advisories = $this->source->advisoriesFor(array_keys($installed));
        $report = [];

        foreach ($installed as $package => $version) {
            $reported = [];

            foreach ($advisories[$package] ?? [] as $advisory) {
                if (!$this->affects($advisory, $version) || $this->isAllowed($advisory, $allowList)) {
                    continue;
                }

                $id = $this->string($advisory['advisoryId'] ?? null) ?? $package.'#'.count($reported);

                $reported[$id] = [
                    'title' => $this->string($advisory['title'] ?? null) ?? $id,
                    'link' => $this->string($advisory['link'] ?? null) ?? '',
                    'cve' => $this->string($advisory['cve'] ?? null),
                    'severity' => Severity::normalize($advisory['severity'] ?? null),
                ];
            }

            if ($reported !== []) {
                // Both Packagist endpoints list advisories in their own order; sorting makes the
                // report identical whichever driver produced it.
                ksort($reported);
                $report[$package] = [
                    // The same values the Enlightn driver reported in 3.x, for published views.
                    'version' => ltrim($version, 'v'),
                    'time' => $lockFile->time($package),
                    'advisories' => $reported,
                ];
            }
        }

        // A stable order keeps reports (and mails) comparable from one run to the next.
        ksort($report);

        return $report;
    }

    /**
     * @param array<string, mixed> $advisory
     */
    private function affects(array $advisory, string $version): bool
    {
        try {
            $installed = new Constraint('==', $this->versionParser->normalize($version));
        } catch (UnexpectedValueException) {
            // Composer itself would refuse such a version; report the advisory rather than
            // silently skipping the package. A false alarm is visible, a missed one is not.
            return true;
        }

        return $this->affectedVersions($advisory)->matches($installed);
    }

    /**
     * @param array<string, mixed> $advisory
     */
    private function affectedVersions(array $advisory): ConstraintInterface
    {
        $range = $this->string($advisory['affectedVersions'] ?? null) ?? '';

        if (!isset($this->constraints[$range])) {
            try {
                $this->constraints[$range] = $this->versionParser->parseConstraints($range);
            } catch (UnexpectedValueException) {
                // Same choice as composer audit: an advisory whose range cannot be parsed affects
                // every version, so it is reported instead of being dropped.
                $this->constraints[$range] = new MatchAllConstraint();
            }
        }

        return $this->constraints[$range];
    }

    /**
     * An advisory can be allowed by its CVE (as with the Enlightn driver), its exact title,
     * its GitHub advisory id (GHSA-...) or its Packagist advisory id (PKSA-...). The ids help
     * for advisories that have no CVE.
     *
     * @param array<string, mixed> $advisory
     * @param array<int, string> $allowList
     */
    private function isAllowed(array $advisory, array $allowList): bool
    {
        if ($allowList === []) {
            return false;
        }

        $identifiers = [
            $advisory['cve'] ?? null,
            $advisory['title'] ?? null,
            $advisory['remoteId'] ?? null,
            $advisory['advisoryId'] ?? null,
        ];

        foreach ($advisory['sources'] ?? [] as $source) {
            $identifiers[] = is_array($source) ? ($source['remoteId'] ?? null) : null;
        }

        $identifiers = array_filter($identifiers, fn ($identifier) => is_string($identifier) && $identifier !== '');

        return array_intersect($identifiers, $allowList) !== [];
    }

    private function string(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? $value : null;
    }
}
