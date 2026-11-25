<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker
    |--------------------------------------------------------------------------
    |
    | Este archivo cargará todas las traducciones de este paquete.
    |
    */

    'subject_new_vulnerabilities' => '{0} Ningún paquete tiene vulnerabilidades conocidas|{1} 1 paquete tiene vulnerabilidades conocidas|[2,*] :count paquetes tienen vulnerabilidades conocidas',
    'title' => 'Titulo',
    'view' => 'Vista',
    'cve' => 'CVE',
    'information' => 'Información',
    'no_recipients_configured' => 'Aún no se ha configurado ningún destinatario.!',
    'body_no_vulnerabilities' => 'Parece que ningún paquete tiene vulnerabilidades conocidas. Puede leer más sobre cómo deshabilitar este mensaje [aquí](https://github.com/jorijn/laravel-security-checker#configuration).',
    'subject_check_failed' => 'No se pudo ejecutar la comprobación de seguridad',
    'body_check_failed' => 'No se pudo ejecutar la comprobación de seguridad de :path, por lo que **no** se ha comprobado si esta aplicación tiene vulnerabilidades conocidas. El error fue:',
    'body_check_failed_hint' => 'La comprobación se ejecutará de nuevo en su próxima hora programada. Si este mensaje sigue apareciendo, asegúrese de que el servidor puede acceder a packagist.org.',
];
