<?php

namespace Jorijn\LaravelSecurityChecker\Formatter;

use Symfony\Component\Console\Output\OutputInterface;

class SimpleFormatter implements FormatterInterface
{
    /**
     * Displays a security report as simple plain text.
     *
     * @param OutputInterface $output
     * @param string          $lockFilePath    The file path to the checked lock file
     * @param array           $vulnerabilities An array of vulnerabilities
     * @param array           $ignored         Advisories left out by the allow list (see
     *                                         ReportsIgnoredAdvisories), with their reasons
     */
    public function displayResults(OutputInterface $output, $lockFilePath, array $vulnerabilities, array $ignored = [])
    {
        $output->writeln(sprintf('Security Check Report: <comment>%s</>', realpath($lockFilePath)));

        if ($count = count($vulnerabilities)) {
            $status = 'CRITICAL';
            $style = 'error';
        } else {
            $status = 'OK';
            $style = 'info';
        }

        $output->writeln(sprintf(
            '<%s>[%s] %d %s known vulnerabilities</>',
            $style,
            $status,
            $count,
            1 === $count ? 'package has' : 'packages have'
        ));

        if (0 !== $count) {
            $output->write("\n");

            foreach ($vulnerabilities as $dependency => $issues) {
                $dependencyFullName = $dependency.' ('.$issues['version'].')';
                $output->writeln('<info>'.$dependencyFullName."\n".str_repeat(
                    '-',
                    strlen($dependencyFullName)
                )."</>\n");

                foreach ($issues['advisories'] as $issue => $details) {
                    $output->write(' * ');
                    // Optional in the report shape, and unknown for many advisories.
                    if (!empty($details['severity'])) {
                        $output->write('['.$details['severity'].'] ');
                    }
                    if ($details['cve']) {
                        $output->write('<comment>'.$details['cve'].': </comment>');
                    }
                    $output->writeln($details['title']);

                    if ('' !== $details['link']) {
                        $output->writeln('   '.$details['link']);
                    }

                    $output->writeln('');
                }
            }
        }

        $this->displayIgnored($output, $ignored);
    }

    /**
     * Lists what the allow list hides, so an accepted risk stays visible (and gets cleaned up
     * once the package is updated) instead of silently disappearing from every report.
     */
    private function displayIgnored(OutputInterface $output, array $ignored): void
    {
        $count = array_sum(array_map(fn (array $package) => count($package['advisories'] ?? []), $ignored));

        if ($count === 0) {
            return;
        }

        $output->writeln(sprintf(
            '<comment>%d %s ignored by the allow list:</>',
            $count,
            1 === $count ? 'advisory is' : 'advisories are'
        ));

        foreach ($ignored as $dependency => $details) {
            foreach ($details['advisories'] ?? [] as $advisory) {
                $output->writeln(sprintf(
                    ' * %s (%s): %s%s',
                    $dependency,
                    $details['version'] ?? '?',
                    !empty($advisory['cve']) ? $advisory['cve'].': ' : '',
                    $advisory['title'] ?? ''
                ));
                $output->writeln('   '.(!empty($advisory['reason'])
                    ? 'Reason: '.$advisory['reason']
                    : 'Allowed by "'.($advisory['allowed_by'] ?? '').'", no reason given'));
            }
        }

        $output->writeln('');
    }
}
