<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Jorijn\LaravelSecurityChecker\Console\Concerns\ChecksForVulnerabilities;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Jorijn\LaravelSecurityChecker\Formatter\JsonFormatter;
use Jorijn\LaravelSecurityChecker\Formatter\SimpleFormatter;
use Symfony\Component\Console\Input\InputOption;

class SecurityCommand extends Command
{
    use ChecksForVulnerabilities;

    /**
     * The supported values of --format; "text" is the report 1.x to 4.0 always printed.
     */
    private const FORMATS = ['text', 'json'];

    /**
     * @var string
     */
    protected $name = 'security-check:now';

    /**
     * @var string
     */
    protected $description = 'Checks composer.lock for known vulnerabilities. '
        .'Exits with 1 when vulnerabilities are found, 2 when the check could not run.';

    /**
     * Execute the command
     */
    public function handle(): int
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        if (!in_array($this->format(), self::FORMATS, true)) {
            // Nothing was checked, so this must not exit with 0 (or 1, "vulnerabilities found").
            $this->error(sprintf(
                'Unknown --format "%s", expected one of: %s.',
                $this->format(),
                implode(', ', self::FORMATS)
            ));

            return self::CHECK_FAILED;
        }

        try {
            $checkResult = $this->checkForVulnerabilities($composerLock);
        } catch (CheckFailedException $e) {
            // The console output and exit code 2 are the alert here; see handleFailedCheck().
            $exitCode = $this->handleFailedCheck($e, $composerLock);

            if ($this->wantsJson()) {
                app(JsonFormatter::class)->displayError($this->getOutput(), $composerLock, $e->getMessage());
            }

            return $exitCode;
        }

        // then display it using the formatter provided
        $formatter = $this->wantsJson() ? app(JsonFormatter::class) : app(SimpleFormatter::class);
        $formatter->displayResults($this->getOutput(), $composerLock, $checkResult, $this->ignoredAdvisories);

        return count($checkResult) > 0 ? self::VULNERABILITIES_FOUND : self::SUCCESS;
    }

    /**
     * Every human-readable line (warnings about the configuration, "the check could not run")
     * goes through here. With --format=json those go to stderr, so stdout holds nothing but the
     * JSON document and `php artisan security-check:now --format=json > report.json` stays
     * parseable. Without a separate stderr (e.g. a buffered test output) they stay on stdout.
     */
    public function line($string, $style = null, $verbosity = null)
    {
        if (!$this->wantsJson()) {
            parent::line($string, $style, $verbosity);

            return;
        }

        // Plain text: the stderr stream has its own formatter, which may not know Laravel's
        // custom styles (like "warning"), and there is nobody to admire colours in a pipe anyway.
        $this->output->getErrorStyle()->writeln((string) $string, $this->parseVerbosity($verbosity));
    }

    /**
     * @return array<int, array<int, mixed>>
     */
    protected function getOptions()
    {
        return [
            ['format', null, InputOption::VALUE_REQUIRED, 'Output format: "text" or "json"', 'text'],
        ];
    }

    private function wantsJson(): bool
    {
        return $this->format() === 'json';
    }

    private function format(): string
    {
        // line() can run before the input is bound (e.g. while Laravel sets the command up).
        if (!isset($this->input) || !$this->input->hasOption('format')) {
            return 'text';
        }

        return strtolower(trim((string) $this->option('format')));
    }
}
