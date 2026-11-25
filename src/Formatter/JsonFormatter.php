<?php

namespace Jorijn\LaravelSecurityChecker\Formatter;

use Symfony\Component\Console\Output\OutputInterface;

/**
 * Prints the report as one JSON document, for CI pipelines and scripts.
 *
 * The output is meant to be parsed, so it is written raw (no console styling) and nothing else
 * may end up on the same stream; SecurityCommand sends its warnings to stderr in this mode.
 */
class JsonFormatter implements FormatterInterface
{
    /**
     * Pretty-printed because people read it in CI logs too; parsers do not care. Invalid UTF-8
     * in an advisory title must never make the whole report disappear, hence the substitution.
     */
    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    /**
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities The report, in the shape described on Checker
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities)
    {
        $this->write($output, [
            'lock_file' => $this->path($lockFilePath),
            'vulnerable_package_count' => count($vulnerabilities),
            'advisory_count' => array_sum(array_map(
                fn (array $package) => count($package['advisories'] ?? []),
                $vulnerabilities
            )),
            // An empty PHP array would encode as [], but consumers expect the same type (an
            // object keyed by package name) whether or not anything was found.
            'packages' => (object) $vulnerabilities,
        ]);
    }

    /**
     * Prints the document for a check that could not run (exit code 2).
     *
     * Without it, a script piping the output into a JSON parser would only see a parse error,
     * and could easily mistake that for "nothing to report".
     */
    public function displayError(OutputInterface $output, string $lockFilePath, string $reason): void
    {
        $this->write($output, [
            'lock_file' => $this->path($lockFilePath),
            'error' => $reason,
        ]);
    }

    private function write(OutputInterface $output, array $document): void
    {
        $output->writeln(json_encode($document, self::FLAGS), OutputInterface::OUTPUT_RAW);
    }

    /**
     * The same path the text report shows; falls back to the given path when composer.lock is
     * missing (realpath() returns false then, and that is exactly when the path matters most).
     */
    private function path(string $lockFilePath): string
    {
        return realpath($lockFilePath) ?: $lockFilePath;
    }
}
