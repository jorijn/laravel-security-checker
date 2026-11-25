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

    'subject_new_vulnerabilities' => '{0} Er zijn geen pakketten met bekende kwetsbaarheden|{1} 1 pakket heeft bekende kwetsbaarheden|[2,*] :count pakketten hebben bekende kwetsbaarheden',
    'title' => 'Titel',
    'view' => 'Bekijken',
    'cve' => 'CVE',
    'information' => 'Informatie',
    'no_recipients_configured' => 'Er zijn nog geen ontvangers geconfigureerd!',
    'body_no_vulnerabilities' => 'Het lijkt erop dat er geen pakketten zijn met bekende kwetsbaarheden. Lees [hier](https://github.com/jorijn/laravel-security-checker#configuration) hoe je dit bericht uit kunt schakelen.',
    'subject_check_failed' => 'De beveiligingscheck kon niet draaien',
    'body_check_failed' => 'De beveiligingscheck van :path kon niet draaien, dus deze applicatie is **niet** gecontroleerd op bekende kwetsbaarheden. De foutmelding was:',
    'body_check_failed_hint' => 'De check draait opnieuw op het volgende geplande moment. Blijft dit bericht terugkomen, controleer dan of de server packagist.org kan bereiken.',
];
