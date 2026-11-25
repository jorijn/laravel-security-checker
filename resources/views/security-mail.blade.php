@component('mail::message')
# {{ $title }}

@foreach ($packages as $package => $report)
## {{ $package }} — {{ $report['version'] }}

@component('mail::table')
| @lang('laravel-security-checker::messages.title') | @lang('laravel-security-checker::messages.severity') | @lang('laravel-security-checker::messages.cve') | @lang('laravel-security-checker::messages.information') |
| :---- | :-- | :-- | :---------- |
@foreach($report['advisories'] as $key => $information)
| {{ $information['title'] }} | {{ $information['severity'] ?? '' }} | {{ $information['cve'] ?? '' }} | [@lang('laravel-security-checker::messages.view')]({{ $information['link'] }})
@endforeach
@endcomponent
{{-- Keep the blank line below: it ends the table's HTML block, so the next package's "##" line is rendered as a heading. --}}

@endforeach

@if (count($packages) === 0)
{{ __('laravel-security-checker::messages.body_no_vulnerabilities') }}
@endif

@endcomponent