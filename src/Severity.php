<?php

namespace Jorijn\LaravelSecurityChecker;

/**
 * The severity levels Packagist uses for advisories (taken from the GitHub Advisory Database),
 * from least to most severe.
 *
 * Not every advisory has one: about 7% of Packagist's feed (mostly FriendsOfPHP-only
 * advisories) has none, and the deprecated Enlightn driver never knows it. Unknown severity is
 * therefore a normal value (null), and it is never filtered out: an advisory we cannot rank
 * might be critical, and a missed critical advisory is worse than one message too many.
 */
final class Severity
{
    public const LEVELS = ['low', 'medium', 'high', 'critical'];

    /**
     * Returns the lower-case level, or null when the value is not a known level.
     */
    public static function normalize(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $value = strtolower(trim($value));

        // GitHub calls it "moderate" in places, Packagist "medium"; both mean the same level.
        if ($value === 'moderate') {
            $value = 'medium';
        }

        return in_array($value, self::LEVELS, true) ? $value : null;
    }

    /**
     * Whether an advisory of the given severity is reported at the given minimum level.
     */
    public static function meets(?string $severity, string $minimum): bool
    {
        $severity = self::normalize($severity);

        if ($severity === null) {
            return true;
        }

        return array_search($severity, self::LEVELS, true) >= array_search($minimum, self::LEVELS, true);
    }
}
