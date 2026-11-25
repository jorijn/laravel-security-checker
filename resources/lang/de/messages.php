<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker
    |--------------------------------------------------------------------------
    |
    | This file will load all the translations for this package.
    |
    */

    'subject_new_vulnerabilities' => '{0} Keine Pakete haben Schwachstellen bekannt|{1} 1 Paket hat Schwachstellen bekannt|[2,*] :count Pakete haben Schwachstellen bekannt',
    'title' => 'Titel',
    'view' => 'Ansehen',
    'cve' => 'CVE',
    'severity' => 'Schweregrad',
    'information' => 'Information',
    'no_recipients_configured' => 'Es wurden noch keine Empfänger konfiguriert!',
    'body_no_vulnerabilities' => 'Es scheint, dass keine Pakete irgendwelche bekannten Schwachstellen haben. [Hier](https://github.com/jorijn/laravel-security-checker#configuration) können Sie mehr über die Deaktivierung dieser Nachricht lesen.',
    'subject_check_failed' => 'Die Sicherheitsprüfung konnte nicht ausgeführt werden',
    'body_check_failed' => 'Die Sicherheitsprüfung von :path konnte nicht ausgeführt werden, daher wurde diese Anwendung **nicht** auf bekannte Schwachstellen geprüft. Der Fehler war:',
    'body_check_failed_hint' => 'Die Prüfung läuft beim nächsten geplanten Termin erneut. Wenn diese Nachricht wiederholt erscheint, stellen Sie sicher, dass der Server packagist.org erreichen kann.',
];
