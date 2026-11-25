@component('mail::message')
# {{ $title }}

{{ __('laravel-security-checker::messages.body_check_failed', ['path' => $composerLock]) }}

@component('mail::panel')
{{ $reason }}
@endcomponent

{{ __('laravel-security-checker::messages.body_check_failed_hint') }}
@endcomponent
