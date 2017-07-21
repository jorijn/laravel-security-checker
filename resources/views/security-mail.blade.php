@component('mail::message')
# {{ $title }}

@foreach ($packages as $package => $report)
## {{ $package }} — {{ $report['version'] }}

@component('mail::table')
| Title | CVE | Information |
| :---- | :-- | :---------- |
@foreach($report['advisories'] as $key => $information)
| {{ $information['title'] }} | {{ $information['cve'] || '' }} | [View]({{ $information['link'] }})
@endforeach
@endcomponent
@endforeach

@endcomponent