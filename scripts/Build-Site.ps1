<#
.SYNOPSIS
    Assembles the registry's website into a new folder: the explorer page (pages/), the signed index (site/index/),
    and GitHub Pages' CNAME and .nojekyll.

.DESCRIPTION
    The page's registry name, title, URL and key are filled in from registry.yaml, so the key the page checks the index
    against is always the one this repository publishes. The index must already be compiled and signed:

        stoker-registry compile . --out site --previous site
        stoker-registry sign site --key <registry key>

.PARAMETER Out
    The folder to write. It must not exist yet.

.EXAMPLE
    ./scripts/Build-Site.ps1 -Out .site-build
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Out
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$out = [IO.Path]::GetFullPath($Out, (Get-Location).Path)
if (Test-Path -LiteralPath $out) { throw "$out already exists; Build-Site writes only into a new folder." }

$index = Join-Path $root 'site/index/v1'
foreach ($file in 'timestamp.json', 'timestamp.json.sig', 'plugins.json.zst') {
    if (-not (Test-Path -LiteralPath (Join-Path $index $file))) {
        throw "site/index/v1/$file is missing: compile and sign the index first."
    }
}

# The four top-level scalars the page needs. registry.yaml writes each on one line, quoted or not.
$registry = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $root 'registry.yaml')) {
    if ($line -match '^(name|title|url|key):\s*"?([^"#]*?)"?\s*(#.*)?$') { $registry[$Matches[1]] = $Matches[2] }
}
foreach ($field in 'name', 'title', 'url', 'key') {
    if (-not $registry[$field]) { throw "registry.yaml has no top-level $field." }
}
$registryUri = [Uri]$registry.url
if ($registryUri.Scheme -ne 'https') { throw "registry.yaml's url must be https." }

function Escape-Html([string]$Text) { [Net.WebUtility]::HtmlEncode($Text) }

New-Item -ItemType Directory -Path $out | Out-Null
Copy-Item -Path (Join-Path $root 'pages/*') -Destination $out -Recurse

$html = Join-Path $out 'index.html'
$text = [IO.File]::ReadAllText($html)
$text = $text.Replace('%%REGISTRY_NAME%%', (Escape-Html $registry.name)).
    Replace('%%REGISTRY_TITLE%%', (Escape-Html $registry.title)).
    Replace('%%REGISTRY_URL%%', (Escape-Html $registry.url)).
    Replace('%%REGISTRY_KEY%%', (Escape-Html $registry.key))
if ($text.Contains('%%')) { throw 'index.html still has a placeholder after filling it in.' }
[IO.File]::WriteAllText($html, $text)

New-Item -ItemType Directory -Path (Join-Path $out 'index') | Out-Null
Copy-Item -Path $index -Destination (Join-Path $out 'index') -Recurse
[IO.File]::WriteAllText((Join-Path $out 'CNAME'), $registryUri.Host)
[IO.File]::WriteAllText((Join-Path $out '.nojekyll'), '')

Write-Host "Built the site for $($registry.name) into $out"
