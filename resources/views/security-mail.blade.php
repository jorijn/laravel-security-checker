@component('mail::message')
# {{ $title }}

@foreach ($packages as $package => $report)
## {{ $package }} — {{ $report['version'] }}

@component('mail::table')
| @lang('laravel-security-checker::messages.title') | @lang('laravel-security-checker::messages.cve') | @lang('laravel-security-checker::messages.information') |
| :---- | :-- | :---------- |
@foreach($report['advisories'] as $key => $information)
| {{ $information['title'] }} | {{ $information['cve'] or '' }} | [@lang('laravel-security-checker::messages.view')]({{ $information['link'] }})
@endforeach
@endcomponent
@endforeach

@if (count($packages) === 0)
{{ __('laravel-security-checker::messages.body_no_vulnerabilities') }}
@endif

@endcomponent