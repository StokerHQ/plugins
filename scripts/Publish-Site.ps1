<#
.SYNOPSIS
    Publishes the website to the gh-pages branch: verifies the signed index, builds the site, and replaces the branch's
    content with it in one commit.

.DESCRIPTION
    The gh-pages branch is checked out in a worktree of its own, made once:

        git worktree add ../plugins-gh-pages gh-pages

    Files in that worktree are removed only through `git rm`, after the script has checked that the folder is a
    worktree of this repository on gh-pages, so nothing outside the branch can be touched. Nothing is pushed without
    -Push.

.PARAMETER Worktree
    The gh-pages worktree.

.PARAMETER Push
    Push gh-pages after committing.

.EXAMPLE
    ./scripts/Publish-Site.ps1 -Worktree ../plugins-gh-pages -Push
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Worktree,
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    $output = & git @Arguments
    if ($LASTEXITCODE) { throw "git $($Arguments -join ' ') failed ($LASTEXITCODE)." }
    $output
}

$root = Split-Path -Parent $PSScriptRoot
$worktree = (Get-Item -LiteralPath ([IO.Path]::GetFullPath($Worktree, (Get-Location).Path))).FullName

# The worktree must be this repository's, on gh-pages, and not the main checkout.
$common = [IO.Path]::GetFullPath((Invoke-Git -C $worktree rev-parse --path-format=absolute --git-common-dir))
$ownCommon = [IO.Path]::GetFullPath((Invoke-Git -C $root rev-parse --path-format=absolute --git-common-dir))
if ($common -ne $ownCommon) { throw "$worktree is not a worktree of $root." }
$top = [IO.Path]::GetFullPath((Invoke-Git -C $worktree rev-parse --show-toplevel))
if ($top -ne [IO.Path]::GetFullPath($worktree)) { throw "$worktree is not the top of its worktree ($top)." }
if ($top -eq [IO.Path]::GetFullPath((Invoke-Git -C $root rev-parse --show-toplevel))) { throw 'The worktree is the main checkout.' }
if ((Invoke-Git -C $worktree rev-parse --abbrev-ref HEAD) -ne 'gh-pages') { throw "$worktree is not on gh-pages." }
if (Invoke-Git -C $worktree status --porcelain) { throw "$worktree has uncommitted changes." }

# The index must verify against the key this repository names before anything is published.
& stoker-registry verify-index (Join-Path $root 'site') --key (Join-Path $root 'registry.yaml')
if ($LASTEXITCODE) { throw 'The index does not verify; nothing was published.' }

$build = Join-Path $root '.site-build'
if (Test-Path -LiteralPath $build) {
    # Only a folder this script made is removed: it is gitignored and holds what Build-Site writes.
    if (-not (Test-Path -LiteralPath (Join-Path $build 'index/v1/timestamp.json'))) { throw "$build is not a site build; remove it by hand." }
    Remove-Item -LiteralPath $build -Recurse -Force
}
& (Join-Path $PSScriptRoot 'Build-Site.ps1') -Out $build

Invoke-Git -C $worktree rm -rq --ignore-unmatch -- . | Out-Null
Copy-Item -Path (Join-Path $build '*') -Destination $worktree -Recurse -Force
Copy-Item -LiteralPath (Join-Path $build '.nojekyll') -Destination $worktree -Force
Invoke-Git -C $worktree add -A | Out-Null

if (-not (Invoke-Git -C $worktree status --porcelain)) {
    Write-Host 'gh-pages already holds this site; nothing to commit.'
} else {
    $serial = (Get-Content -Raw -LiteralPath (Join-Path $build 'index/v1/timestamp.json') | ConvertFrom-Json).serial
    $indexChanged = Invoke-Git -C $worktree diff --cached --name-only -- index
    $message = if ($indexChanged) { "Publish the index, serial $serial" } else { 'Publish the site' }
    Invoke-Git -C $worktree commit -q -m $message | Out-Null
    Write-Host "Committed to gh-pages: $message"
}
Remove-Item -LiteralPath $build -Recurse -Force

if ($Push) {
    Invoke-Git -C $worktree push -q origin gh-pages | Out-Null
    Write-Host 'Pushed gh-pages.'
}
