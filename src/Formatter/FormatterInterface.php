<?php

namespace Jorijn\LaravelSecurityChecker\Formatter;

use Symfony\Component\Console\Output\OutputInterface;

interface FormatterInterface
{
    /**
     * Displays a security report as json.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities);
}
