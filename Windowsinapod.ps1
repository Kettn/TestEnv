[CmdletBinding()]
param(
  [switch]$TimeStamp,
  [switch]$FullCheck
)

function returnHotFixID {
  param(
    [string]$title
  )
  if (($title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value) {
    return (($title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value)
  }
  elseif (($title | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value) {
    return (($title | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value)
  }
}

Function Start-ACLCheck {
  param(
    $Target, $ServiceName)
  if ($null -ne $target) {
    try {
      $ACLObject = Get-Acl $target -ErrorAction SilentlyContinue
    }
    catch { $null }
    
    if ($ACLObject) { 
      $Identity = @()
      $Identity += "$env:COMPUTERNAME\$env:USERNAME"
      if ($ACLObject.Owner -like $Identity ) { Write-Host "$Identity has ownership of $Target" -ForegroundColor Red }
      whoami.exe /groups /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty 'group name' | ForEach-Object { $Identity += $_ }
      $IdentityFound = $false
      foreach ($i in $Identity) {
        $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }
        $UserPermission = ""
        switch -WildCard ($Permission.FileSystemRights) {
          "FullControl" { $userPermission = "FullControl"; $IdentityFound = $true }
          "Write*" { $userPermission = "Write"; $IdentityFound = $true }
          "Modify" { $userPermission = "Modify"; $IdentityFound = $true }
        }
        Switch ($permission.RegistryRights) {
          "FullControl" { $userPermission = "FullControl"; $IdentityFound = $true }
        }
        if ($UserPermission) {
          if ($ServiceName) { Write-Host "$ServiceName found with permissions issue:" -ForegroundColor Red }
          Write-Host -ForegroundColor red  "Identity $($permission.IdentityReference) has '$userPermission' perms for $Target"
        }
      }    
      if ($IdentityFound -eq $false) {
        if ($Target.Length -gt 3) {
          $Target = Split-Path $Target
          Start-ACLCheck $Target -ServiceName $ServiceName
        }
      }
    }
    else {
      $Target = Split-Path $Target
      Start-ACLCheck $Target $ServiceName
    }
  }
}

Function UnquotedServicePathCheck {
  Write-Host "Fetching the list of services, this may take a while...";
  $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
  if ($($services | Measure-Object).Count -lt 1) {
    Write-Host "No unquoted service paths were found";
  }
  else {
    $services | ForEach-Object {
      Write-Host "Unquoted Service Path found!" -ForegroundColor red
      Write-Host Name: $_.Name
      Write-Host PathName: $_.PathName
      Write-Host StartName: $_.StartName 
      Write-Host StartMode: $_.StartMode
      Write-Host Running: $_.State
    } 
  }
}

function TimeElapsed { Write-Host "Time Running: $($stopwatch.Elapsed.Minutes):$($stopwatch.Elapsed.Seconds)" }

Function Get-ClipBoardText {
  Add-Type -AssemblyName PresentationCore
  $text = [Windows.Clipboard]::GetText()
  if ($text) {
    Write-Host ""
    if ($TimeStamp) { TimeElapsed }
    Write-Host -ForegroundColor Blue "=========|| ClipBoard text found:"
    Write-Host $text
    
  }
}
function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) {
  for ($i = 0; $i -lt $Text.Length; $i++) {
    Write-Host $Text[$i] -Foreground $Color[$i] -NoNewline
  }
  Write-Host
}

$password = $true
$username = $true
$webAuth = $true

$regexSearch = @{}

if ($password) {
  $regexSearch.add("Simple Passwords1", "pass.*[=:].+")
  $regexSearch.add("Simple Passwords2", "pwd.*[=:].+")
  $regexSearch.add("Apr1 MD5", '\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $regexSearch.add("Apache SHA", "\{SHA\}[0-9a-zA-Z/_=]{10,}")
  $regexSearch.add("Blowfish", '\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*')
  $regexSearch.add("Drupal", '\$S\$[a-zA-Z0-9_/\.]{52}')
  $regexSearch.add("Joomlavbulletin", "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
  $regexSearch.add("Linux MD5", '\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $regexSearch.add("phpbb3", '\$H\$[a-zA-Z0-9_/\.]{31}')
  $regexSearch.add("sha512crypt", '\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}')
  $regexSearch.add("Wordpress", '\$P\$[a-zA-Z0-9_/\.]{31}')
  $regexSearch.add("md5", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha1", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha256", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha512", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")  
  $regexSearch.add("Base64", "(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")

}
if ($username) {
  $regexSearch.add("Usernames1", "username[=:].+")
  $regexSearch.add("Usernames2", "user[=:].+")
  $regexSearch.add("Usernames3", "login[=:].+")
  $regexSearch.add("Emails", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
  $regexSearch.add("Net user add", "net user .+ /add")
}

if ($apiANDToken) {
  $regexSearch.add("Artifactory API Token", "AKC[a-zA-Z0-9]{10,}")
  $regexSearch.add("Artifactory Password", "AP[0-9ABCDEF][a-zA-Z0-9]{8,}")
  $regexSearch.add("Adafruit API Key", "([a-z0-9_-]{32})")
  $regexSearch.add("Adafruit API Key", "([a-z0-9_-]{32})")
  $regexSearch.add("Adobe Client Id (Oauth Web)", "(adobe[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32})['""]")
  $regexSearch.add("Abode Client Secret", "(p8e-)[a-z0-9]{32}")
  $regexSearch.add("Age Secret Key", "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")
  $regexSearch.add("Airtable API Key", "([a-z0-9]{17})")
  $regexSearch.add("Alchemi API Key", "(alchemi[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9-]{32})['""]")
  $regexSearch.add("Artifactory API Key & Password", "[""']AKC[a-zA-Z0-9]{10,}[""']|[""']AP[0-9ABCDEF][a-zA-Z0-9]{8,}[""']")
  $regexSearch.add("Atlassian API Key", "(atlassian[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{24})['""]")
  $regexSearch.add("Binance API Key", "(binance[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{64})['""]")
  $regexSearch.add("Bitbucket Client Id", "((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""])")
  $regexSearch.add("Bitbucket Client Secret", "((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9_\-]{64})['""])")
  $regexSearch.add("BitcoinAverage API Key", "(bitcoin.?average[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{43})['""]")
  $regexSearch.add("Bitquery API Key", "(bitquery[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9]{32})['""]")
  $regexSearch.add("Bittrex Access Key and Access Key", "([a-z0-9]{32})")
  $regexSearch.add("Birise API Key", "(bitrise[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9_\-]{86})['""]")
  $regexSearch.add("Block API Key", "(block[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})['""]")
  $regexSearch.add("Blockchain API Key", "mainnet[a-zA-Z0-9]{32}|testnet[a-zA-Z0-9]{32}|ipfs[a-zA-Z0-9]{32}")
  $regexSearch.add("Blockfrost API Key", "(blockchain[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[0-9a-f]{12})['""]")
  $regexSearch.add("Box API Key", "(box[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{32})['""]")
  $regexSearch.add("Bravenewcoin API Key", "(bravenewcoin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{50})['""]")
  $regexSearch.add("Clearbit API Key", "sk_[a-z0-9]{32}")
  $regexSearch.add("Clojars API Key", "(CLOJARS_)[a-zA-Z0-9]{60}")
  $regexSearch.add("Coinbase Access Token", "([a-z0-9_-]{64})")
  $regexSearch.add("Coinlayer API Key", "(coinlayer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $regexSearch.add("Coinlib API Key", "(coinlib[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{16})['""]")
  $regexSearch.add("Confluent Access Token & Secret Key", "([a-z0-9]{16})")
  $regexSearch.add("Contentful delivery API Key", "(contentful[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_\-]{43})['""]")
  $regexSearch.add("Covalent API Key", "ckey_[a-z0-9]{27}")
  $regexSearch.add("Charity Search API Key", "(charity.?search[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $regexSearch.add("Databricks API Key", "dapi[a-h0-9]{32}")
  $regexSearch.add("DDownload API Key", "(ddownload[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{22})['""]")
  $regexSearch.add("Defined Networking API token", "(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})")
  $regexSearch.add("Discord API Key, Client ID & Client Secret", "((discord[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-h0-9]{64}|[0-9]{18}|[a-z0-9=_\-]{32})['""])")
  $regexSearch.add("Droneci Access Token", "([a-z0-9]{32})")
  $regexSearch.add("Dropbox API Key", "sl.[a-zA-Z0-9_-]{136}")
  $regexSearch.add("Doppler API Key", "(dp\.pt\.)[a-zA-Z0-9]{43}")
  $regexSearch.add("Dropbox API secret/key, short & long lived API Key", "(dropbox[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{15}|sl\.[a-z0-9=_\-]{135}|[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9_=\-]{43})['""]")
  $regexSearch.add("Duffel API Key", "duffel_(test|live)_[a-zA-Z0-9_-]{43}")
  $regexSearch.add("Dynatrace API Key", "dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64}")
  $regexSearch.add("EasyPost API Key", "EZAK[a-zA-Z0-9]{54}")
  $regexSearch.add("EasyPost test API Key", "EZTK[a-zA-Z0-9]{54}")
  $regexSearch.add("Etherscan API Key", "(etherscan[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{34})['""]")
  $regexSearch.add("Etsy Access Token", "([a-z0-9]{24})")
  $regexSearch.add("Facebook Access Token", "EAACEdEose0cBA[0-9A-Za-z]+")
  $regexSearch.add("Fastly API Key", "(fastly[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_\-]{32})['""]")
  $regexSearch.add("Finicity API Key & Client Secret", "(finicity[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32}|[a-z0-9]{20})['""]")
  $regexSearch.add("Flickr Access Token", "([a-z0-9]{32})")
  $regexSearch.add("Flutterweave Keys", "FLWPUBK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST[a-hA-H0-9]{12}")
  $regexSearch.add("Frame.io API Key", "fio-u-[a-zA-Z0-9_=\-]{64}")
  $regexSearch.add("Freshbooks Access Token", "([a-z0-9]{64})")
  $regexSearch.add("Github", "github(.{0,20})?['""][0-9a-zA-Z]{35,40}")
  $regexSearch.add("Github App Token", "(ghu|ghs)_[0-9a-zA-Z]{36}")
  $regexSearch.add("Github OAuth Access Token", "gho_[0-9a-zA-Z]{36}")
  $regexSearch.add("Github Personal Access Token", "ghp_[0-9a-zA-Z]{36}")
  $regexSearch.add("Github Refresh Token", "ghr_[0-9a-zA-Z]{76}")
  $regexSearch.add("GitHub Fine-Grained Personal Access Token", "github_pat_[0-9a-zA-Z_]{82}")
  $regexSearch.add("Gitlab Personal Access Token", "glpat-[0-9a-zA-Z\-]{20}")
  $regexSearch.add("GitLab Pipeline Trigger Token", "glptt-[0-9a-f]{40}")
  $regexSearch.add("GitLab Runner Registration Token", "GR1348941[0-9a-zA-Z_\-]{20}")
  $regexSearch.add("Gitter Access Token", "([a-z0-9_-]{40})")
  $regexSearch.add("GoCardless API Key", "live_[a-zA-Z0-9_=\-]{40}")
  $regexSearch.add("GoFile API Key", "(gofile[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{32})['""]")
  $regexSearch.add("Google API Key", "AIza[0-9A-Za-z_\-]{35}")
  $regexSearch.add("Google Cloud Platform API Key", "(google|gcp|youtube|drive|yt)(.{0,20})?['""][AIza[0-9a-z_\-]{35}]['""]")
  $regexSearch.add("Google Drive Oauth", "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")
  $regexSearch.add("Google Oauth Access Token", "ya29\.[0-9A-Za-z_\-]+")
  $regexSearch.add("Google (GCP) Service-account", """type.+:.+""service_account")
  $regexSearch.add("Grafana API Key", "eyJrIjoi[a-z0-9_=\-]{72,92}")
  $regexSearch.add("Grafana cloud api token", "glc_[A-Za-z0-9\+/]{32,}={0,2}")
  $regexSearch.add("Grafana service account token", "(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})")
  $regexSearch.add("Hashicorp Terraform user/org API Key", "[a-z0-9]{14}\.atlasv1\.[a-z0-9_=\-]{60,70}")
  $regexSearch.add("Heroku API Key", "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
  $regexSearch.add("Hubspot API Key", "['""][a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12}['""]")
  $regexSearch.add("Instatus API Key", "(instatus[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $regexSearch.add("Intercom API Key & Client Secret/ID", "(intercom[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_]{60}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['""]")
  $regexSearch.add("Ionic API Key", "(ionic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""](ion_[a-z0-9]{42})['""]")
  $regexSearch.add("JSON Web Token", "(ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2})")
  $regexSearch.add("Kraken Access Token", "([a-z0-9\/=_\+\-]{80,90})")
  $regexSearch.add("Kucoin Access Token", "([a-f0-9]{24})")
  $regexSearch.add("Kucoin Secret Key", "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $regexSearch.add("Launchdarkly Access Token", "([a-z0-9=_\-]{40})")
  $regexSearch.add("Linear API Key", "(lin_api_[a-zA-Z0-9]{40})")
  $regexSearch.add("Linear Client Secret/ID", "((linear[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32})['""])")
  $regexSearch.add("LinkedIn Client ID", "linkedin(.{0,20})?['""][0-9a-z]{12}['""]")
  $regexSearch.add("LinkedIn Secret Key", "linkedin(.{0,20})?['""][0-9a-z]{16}['""]")
  $regexSearch.add("Lob API Key", "((lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]((live|test)_[a-f0-9]{35})['""])|((lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]((test|live)_pub_[a-f0-9]{31})['""])")
  $regexSearch.add("Lob Publishable API Key", "((test|live)_pub_[a-f0-9]{31})")
  $regexSearch.add("MailboxValidator", "(mailbox.?validator[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{20})['""]")
  $regexSearch.add("Mailchimp API Key", "[0-9a-f]{32}-us[0-9]{1,2}")
  $regexSearch.add("Mailgun API Key", "key-[0-9a-zA-Z]{32}'")
  $regexSearch.add("Mailgun Public Validation Key", "pubkey-[a-f0-9]{32}")
  $regexSearch.add("Mailgun Webhook signing key", "[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}")
  $regexSearch.add("Mapbox API Key", "(pk\.[a-z0-9]{60}\.[a-z0-9]{22})")
  $regexSearch.add("Mattermost Access Token", "([a-z0-9]{26})")
  $regexSearch.add("MessageBird API Key & API client ID", "(messagebird[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{25}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['""]")
  $regexSearch.add("Microsoft Teams Webhook", "https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}")
  $regexSearch.add("MojoAuth API Key", "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
  $regexSearch.add("Netlify Access Token", "([a-z0-9=_\-]{40,46})")
  $regexSearch.add("New Relic User API Key, User API ID & Ingest Browser API Key", "(NRAK-[A-Z0-9]{27})|((newrelic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{64})['""])|(NRJS-[a-f0-9]{19})")
  $regexSearch.add("Nownodes", "(nownodes[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9]{32})['""]")
  $regexSearch.add("Npm Access Token", "(npm_[a-zA-Z0-9]{36})")
  $regexSearch.add("Nytimes Access Token", "([a-z0-9=_\-]{32})")
  $regexSearch.add("Okta Access Token", "([a-z0-9=_\-]{42})")
  $regexSearch.add("OpenAI API Token", "sk-[A-Za-z0-9]{48}")
  $regexSearch.add("ORB Intelligence Access Key", "['""][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['""]")
  $regexSearch.add("Pastebin API Key", "(pastebin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $regexSearch.add("PayPal Braintree Access Token", 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')
  $regexSearch.add("Picatic API Key", "sk_live_[0-9a-z]{32}")
  $regexSearch.add("Pinata API Key", "(pinata[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{64})['""]")
  $regexSearch.add("Planetscale API Key", "pscale_tkn_[a-zA-Z0-9_\.\-]{43}")
  $regexSearch.add("PlanetScale OAuth token", "(pscale_oauth_[a-zA-Z0-9_\.\-]{32,64})")
  $regexSearch.add("Planetscale Password", "pscale_pw_[a-zA-Z0-9_\.\-]{43}")
  $regexSearch.add("Plaid API Token", "(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $regexSearch.add("Plaid Client ID", "([a-z0-9]{24})")
  $regexSearch.add("Plaid Secret key", "([a-z0-9]{30})")
  $regexSearch.add("Prefect API token", "(pnu_[a-z0-9]{36})")
  $regexSearch.add("Postman API Key", "PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}")
  $regexSearch.add("Private Keys", "\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
  $regexSearch.add("Pulumi API Key", "pul-[a-f0-9]{40}")
  $regexSearch.add("PyPI upload token", "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")
  $regexSearch.add("Quip API Key", "(quip[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{15}=\|[0-9]{10}\|[a-zA-Z0-9\/+]{43}=)['""]")
  $regexSearch.add("RapidAPI Access Token", "([a-z0-9_-]{50})")
  $regexSearch.add("Rubygem API Key", "rubygems_[a-f0-9]{48}")
  $regexSearch.add("Readme API token", "rdme_[a-z0-9]{70}")
  $regexSearch.add("Sendbird Access ID", "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $regexSearch.add("Sendbird Access Token", "([a-f0-9]{40})")
  $regexSearch.add("Sendgrid API Key", "SG\.[a-zA-Z0-9_\.\-]{66}")
  $regexSearch.add("Sendinblue API Key", "xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}")
  $regexSearch.add("Sentry Access Token", "([a-f0-9]{64})")
  $regexSearch.add("Shippo API Key, Access Token, Custom Access Token, Private App Access Token & Shared Secret", "shippo_(live|test)_[a-f0-9]{40}|shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}")
  $regexSearch.add("Sidekiq Secret", "([a-f0-9]{8}:[a-f0-9]{8})")
  $regexSearch.add("Sidekiq Sensitive URL", "([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)")
  $regexSearch.add("Slack Token", "xox[baprs]-([0-9a-zA-Z]{10,48})?")
  $regexSearch.add("Smarksheel API Key", "(smartsheet[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{26})['""]")
  $regexSearch.add("Square Access Token", "sqOatp-[0-9A-Za-z_\-]{22}")
  $regexSearch.add("Square API Key", "EAAAE[a-zA-Z0-9_-]{59}")
  $regexSearch.add("Square Oauth Secret", "sq0csp-[ 0-9A-Za-z_\-]{43}")
  $regexSearch.add("Stytch API Key", "secret-.*-[a-zA-Z0-9_=\-]{36}")
  $regexSearch.add("Stripe Access Token & API Key", "(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}")
  $regexSearch.add("SumoLogic Access ID", "([a-z0-9]{14})")
  $regexSearch.add("SumoLogic Access Token", "([a-z0-9]{64})")
  $regexSearch.add("Telegram Bot API Token", "[0-9]+:AA[0-9A-Za-z\\-_]{33}")
  $regexSearch.add("Travis CI Access Token", "([a-z0-9]{22})")
  $regexSearch.add("Trello API Key", "(trello[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-z]{32})['""]")
  $regexSearch.add("Twilio API Key", "SK[0-9a-fA-F]{32}")
  $regexSearch.add("Twitch API Key", "(twitch[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{30})['""]")
  $regexSearch.add("Twitter Client ID", "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['""][0-9a-z]{18,25}")
  $regexSearch.add("Twitter Bearer Token", "(A{22}[a-zA-Z0-9%]{80,100})")
  $regexSearch.add("Twitter Oauth", "[tT][wW][iI][tT][tT][eE][rR].{0,30}['""\\s][0-9a-zA-Z]{35,44}['""\\s]")
  $regexSearch.add("Twitter Secret Key", "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['""][0-9a-z]{35,44}")
  $regexSearch.add("Typeform API Key", "tfp_[a-z0-9_\.=\-]{59}")
  $regexSearch.add("URLScan API Key", "['""][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['""]")
  $regexSearch.add("Vault Token", "[sb]\.[a-zA-Z0-9]{24}")
  $regexSearch.add("Yandex Access Token", "(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})")
  $regexSearch.add("Yandex API Key", "(AQVN[A-Za-z0-9_\-]{35,38})")
  $regexSearch.add("Yandex AWS Access Token", "(YC[a-zA-Z0-9_\-]{38})")
  $regexSearch.add("Web3 API Key", "(web3[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.?[A-Za-z0-9_.+/=\-]*)['""]")
  $regexSearch.add("Zendesk Secret Key", "([a-z0-9]{40})")
  $regexSearch.add("Generic API Key", "((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

if ($webAuth) {
  $regexSearch.add("Authorization Basic", "basic [a-zA-Z0-9_:\.=\-]+")
  $regexSearch.add("Authorization Bearer", "bearer [a-zA-Z0-9_\.=\-]+")
  $regexSearch.add("Alibaba Access Key ID", "(LTAI)[a-z0-9]{20}")
  $regexSearch.add("Alibaba Secret Key", "(alibaba[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{30})['""]")
  $regexSearch.add("Asana Client ID", "((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9]{16})['""])|((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""])")
  $regexSearch.add("AWS Client ID", "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
  $regexSearch.add("AWS MWS Key", "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
  $regexSearch.add("AWS Secret Key", "aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
  $regexSearch.add("AWS AppSync GraphQL Key", "da2-[a-z0-9]{26}")
  $regexSearch.add("Basic Auth Credentials", "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
  $regexSearch.add("Beamer Client Secret", "(beamer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""](b_[a-z0-9=_\-]{44})['""]")
  $regexSearch.add("Cloudinary Basic Auth", "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
  $regexSearch.add("Facebook Client ID", "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9]{13,17}")
  $regexSearch.add("Facebook Oauth", "[fF][aA][cC][eE][bB][oO][oO][kK].*['|""][0-9a-f]{32}['|""]")
  $regexSearch.add("Facebook Secret Key", "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9a-f]{32}")
  $regexSearch.add("Jenkins Creds", "<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
  $regexSearch.add("Generic Secret", "[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
  $regexSearch.add("Basic Auth", "//(.+):(.+)@")
  $regexSearch.add("PHP Passwords", "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
  $regexSearch.add("Config Secrets (Passwd / Credentials)", "passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
  $regexSearch.add("Generiac API tokens search", "(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

$regexSearch.add("IPs", "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
$Drives = Get-PSDrive | Where-Object { $_.Root -like "*:\" }
$fileExtensions = @("*.xml", "*.txt", "*.conf", "*.config", "*.cfg", "*.ini", ".y*ml", "*.log", "*.bak")

$stopwatch = [system.diagnostics.stopwatch]::StartNew()

if($FullCheck){
  Write-Host "**Full Check Enabled. This will significantly increase false positives in registry / folder check for Usernames / Passwords.**"
}
  
Write-Host -BackgroundColor Red -ForegroundColor White  " hehe it works >:D "

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host "~Sysinfo~"
systeminfo.exe

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~SpicyFixes~"
$Hotfix = Get-HotFix | Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue | Select-Object HotfixID, Description, InstalledBy, InstalledOn
$Hotfix | Format-Table -AutoSize

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~InstalledVerticalDates~"

$session = (New-Object -ComObject 'Microsoft.Update.Session')
$history = $session.QueryHistory("", 0, 1000) | Select-Object ResultCode, Date, Title

$HotfixUnique = @()

$HotFixReturnNum = @()

for ($i = 0; $i -lt $history.Count; $i++) {
  $check = returnHotFixID -title $history[$i].Title
  if ($HotfixUnique -like $check) {
  }
  else {
    $HotfixUnique += $check
    $HotFixReturnNum += $i
  }
}
$FinalHotfixList = @()

$hotfixreturnNum | ForEach-Object {
  $HotFixItem = $history[$_]
  $Result = $HotFixItem.ResultCode
  switch ($Result) {
    1 {
      $Result = "Missing/Superseded"
    }
    2 {
      $Result = "Succeeded"
    }
    3 {
      $Result = "Succeeded With Errors"
    }
    4 {
      $Result = "Failed"
    }
    5 {
      $Result = "Canceled"
    }
  }
  $FinalHotfixList += [PSCustomObject]@{
    Result = $Result
    Date   = $HotFixItem.Date
    Title  = $HotFixItem.Title
  }    
}
$FinalHotfixList | Format-Table -AutoSize


if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~How do you operate a car info~"
Add-Type -AssemblyName System.Management

$diskSearcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")
$systemDrives = $diskSearcher.Get()

foreach ($drive in $systemDrives) {
  $driveLetter = $drive.DeviceID
  $driveLabel = $drive.VolumeName
  $driveSize = [math]::Round($drive.Size / 1GB, 2)
  $driveFreeSpace = [math]::Round($drive.FreeSpace / 1GB, 2)

  Write-Output "Drive: $driveLetter"
  Write-Output "Label: $driveLabel"
  Write-Output "Size: $driveSize GB"
  Write-Output "Free Space: $driveFreeSpace GB"
  Write-Output ""
}

if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Antibiotic Inspection~"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Fishingnet-account-info~"
net accounts

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Front Register check~"

 
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Logging settings~"
if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
  Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
}
else {
  Write-Host ""
}


if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~WEF front register~"
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
  Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
}
else {
}

 
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Amount of circles run check~"
if (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') { Write-Host "LAPS dll found on this machine at C:\Program Files\LAPS\CSE\" -ForegroundColor Green }
elseif (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll' ) { Write-Host "LAPS dll found on this machine at C:\Program Files (x86)\LAPS\CSE\" -ForegroundColor Green }
else { Write-Host "No circles ran" }
if ((Get-ItemProperty HKLM:\Software\Policies\Microsoft Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { Write-Host "LAPS registry key found on this machine" -ForegroundColor Green }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~W Digestion Check~"
$WDigest = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential
switch ($WDigest) {
  0 { Write-Host "Value 0 found. Plain-text Passwords are not stored in LSASS" }
  1 { Write-Host "Value 1 found. Plain-text Passwords may be stored in LSASS" -ForegroundColor red }
  Default { Write-Host "Couldnt find name in front desk registration book" }
}

 
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~TSA but replace T with L defence level check~"
$RunAsPPL = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
$RunAsPPLBoot = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPLBoot
switch ($RunAsPPL) {
  2 { Write-Host "RunAsPPL: 2. Enabled without UEFI Lock" }
  1 { Write-Host "RunAsPPL: 1. Enabled with UEFI Lock" }
  0 { Write-Host "RunAsPPL: 0. LSA Protection Disabled. Try mimikatz." -ForegroundColor red }
  Default { "Failed search" }
}
if ($RunAsPPLBoot) { Write-Host "RunAsPPLBoot: $RunAsPPLBoot" }

 
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~credguard inspect~"
$LsaCfgFlags = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags
switch ($LsaCfgFlags) {
  2 { Write-Host "LsaCfgFlags 2. Enabled without UEFI Lock" }
  1 { Write-Host "LsaCfgFlags 1. Enabled with UEFI Lock" }
  0 { Write-Host "LsaCfgFlags 0. LsaCfgFlags Disabled." -ForegroundColor red }
  Default { "Couldnt find what I was looking for" }
}

 
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Loooking for cr3ds that were left behind~"
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
  (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT").CACHEDLOGONSCOUNT
}

if ($TimeStamp) { TimeElapsed }
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword


Write-Host "space :)"
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~aRR Dee CeeMan evaluation"

if (Test-Path "$env:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") {
  Write-Host "RDCMan Settings Found at: $($env:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ForegroundColor Red
}
else { Write-Host "unlucky, no treasure" }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Resulting Dropped Pear that remain check~"

Write-Host "HongKongEY Users"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
  if (Test-Path "registry::HKEY_USERS\$HKUSID\Software\Microsoft\Terminal Server Client\Default") {
    Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_USERS\$HKUSID\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"
  }
  else { Write-Host "Not found for $($_.Name)" }
}

Write-Host "HongKongCinematicUniverse"
if (Test-Path "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default") {
  Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"
}
else { Write-Host "HongKongCinematicUniverse flopped in cinemas" }

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~playdoh creations remain?~"

if (Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions) {
  Get-ChildItem HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions | ForEach-Object {
    $RegKeyName = Split-Path $_.Name -Leaf
    Write-Host "Key: $RegKeyName"
    @("HostName", "PortNumber", "UserName", "PublicKeyFile", "PortForwardings", "ConnectionSharing", "ProxyUsername", "ProxyPassword") | ForEach-Object {
      Write-Host "$_ :"
      Write-Host "$((Get-ItemProperty  HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\$RegKeyName).$_)"
    }
  }
}
else { Write-Host "No playdoh creations were added to the register or could not be found there" }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~SSH Cheques~"
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Checking Playdoh known hosts"
if (Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys) { 
  Write-Host "$((Get-Item -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)"
}
else { Write-Host "keys to playdoh closet not found" }

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Looking for Open Secure Socket Shell Keyring"
if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) { Write-Host "Found lock fixers" -ForegroundColor Yellow }
else { Write-Host "No OpenSSH Keys found." }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Searching for WindowsVirtualNetworkConnection P4ssw0rd5"
if ( Test-Path "HKCU:\Software\ORL\WinVNC3\Password") { Write-Host " WinVNC found at HKCU:\Software\ORL\WinVNC3\Password" }else { Write-Host "No WinVNC found." }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Looking for SNail MulitPlayer wordpasses~"
if ( Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" ) { Write-Host "SNPM Key found at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" }else { Write-Host "No SNPM found." }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Looking for TightVNC wordPasses~"
if ( Test-Path "HKCU:\Software\TightVNC\Server") { Write-Host "TightVNC key found at HKCU:\Software\TightVNC\Server" }else { Write-Host "No TightVNC found." }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Unit ACess Settings"
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 1) {
}
else { Write-Host "Not equal to one" }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~What was run recently?~"

Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
  $property = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
  $HKUSID | ForEach-Object {
    if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
      Write-Host -ForegroundColor Blue "~another what was run recently?~"
      foreach ($p in $property) {
        Write-Host "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))" 
      }
    }
  }
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~another what was run recently?~"
$property = (Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
foreach ($p in $property) {
  Write-Host "$((Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))"
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~AIE Check (Always start off with high elevation)~"
 
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) {
  Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer).AlwaysInstallElevated = 1" -ForegroundColor red
}
 
if ((Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) { 
  Write-Host "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer).AlwaysInstallElevated = 1" -ForegroundColor red
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Powerful Snail info~"

(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine).PowerShellVersion | ForEach-Object {
  Write-Host "PowerShell $_ available"
}
(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine).PowerShellVersion | ForEach-Object {
  Write-Host  "PowerShell $_ available"
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Powerful Snail Registry Check~"

if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
 

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "Powerful Snail Racingmodule reassurance"
if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
 

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "PowerSnail blockages"
 
if ( Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "SussyW if equal to 1, if true, maybe sus"
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) {
  Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
}
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer" -ErrorAction SilentlyContinue).UseWUServer) {
  (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer").UseWUServer
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~World wide web configuration HK things~"

$property = (Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach ($p in $property) {
  Write-Host "$p - $((Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-ErrorAction SilentlyContinue).getValue($p))"
}
 
$property = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach ($p in $property) {
  Write-Host "$p - $((Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-ErrorAction SilentlyContinue).getValue($p))"
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Currently participating in a Marathon business processes~"


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Determining which runners can run which races~"
Get-Process | Select-Object Path -Unique | ForEach-Object { Start-ACLCheck -Target $_.path }

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~the Syst3m processessssseseses~"
Start-Process tasklist -ArgumentList '/v /fi "username eq system"' -Wait -NoNewWindow

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Butler activity pathway is compromised check~"
Write-Host "Checking for vulnerable service .exe"
$UniqueServices = @{}
Get-WmiObject Win32_Service | Where-Object { $_.PathName -like '*.exe*' } | ForEach-Object {
  $Path = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
  $UniqueServices[$Path] = $_.Name
}
foreach ( $h in ($UniqueServices | Select-Object -Unique).GetEnumerator()) {
  Start-ACLCheck -Target $h.Name -ServiceName $h.Value
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Asessing paths to determine if they are not caged~"


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Assessing who has permission to write into the registrar"
Write-Host "This will take some time."

Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object {
  $target = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:")
  Start-aclcheck -Target $target
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Checking to see if the tasks we've set have any possible stoppers~"
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Can I get to where tasks are held?~"
if (Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue) {
  Write-Host "Access confirmed"
  Get-ChildItem "c:\windows\system32\tasks"
}
else {
  Write-Host "No bigboy access to folder"
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
    $Actions = $_.Actions.Execute
    if ($Actions -ne $null) {
      foreach ($a in $actions) {
        if ($a -like "%windir%*") { $a = $a.replace("%windir%", $Env:windir) }
        elseif ($a -like "%SystemRoot%*") { $a = $a.replace("%SystemRoot%", $Env:windir) }
        elseif ($a -like "%localappdata%*") { $a = $a.replace("%localappdata%", "$env:UserProfile\appdata\local") }
        elseif ($a -like "%appdata%*") { $a = $a.replace("%localappdata%", $env:Appdata) }
        $a = $a.Replace('"', '')
        Start-ACLCheck -Target $a
        Write-Host "`n"
        Write-Host "TaskName: $($_.TaskName)"
        Write-Host "-------------"
        [pscustomobject]@{
          LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
          NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
          Status     = $_.State
          Command    = $_.Actions.execute
          Arguments  = $_.Actions.Arguments 
        } | Write-Host
      } 
    }
  }
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~New company culture check~"
@("C:\Documents and Settings\All Users\Start Menu\Programs\Startup",
  "C:\Documents and Settings\$env:Username\Start Menu\Programs\Startup", 
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", 
  "$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
  if (Test-Path $_) {
    Start-ACLCheck $_
    Get-ChildItem -Recurse -Force -Path $_ | ForEach-Object {
      $SubItem = $_.FullName
      if (Test-Path $SubItem) { 
        Start-ACLCheck -Target $SubItem
      }
    }
  }
}
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========|| STARTUP APPS Registry Check"

@("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
  "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
  "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
  $ROPath = $_
  (Get-Item $_) | ForEach-Object {
    $ROProperty = $_.property
    $ROProperty | ForEach-Object {
      Start-ACLCheck ((Get-ItemProperty -Path $ROPath).$_ -split '(?<=\.exe\b)')[0].Trim('"')
    }
  }
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "Apps that are around"

Get-CimInstance -class win32_Product | Select-Object Name, Version | 
ForEach-Object {
  Write-Host $("{0} : {1}" -f $_.Name, $_.Version)  
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "Finding b4sh 3x3"
Get-ChildItem C:\Windows\WinSxS\ -Filter "amd64_microsoft-windows-lxss-bash*" | ForEach-Object {
  Write-Host $((Get-ChildItem $_.FullName -Recurse -Filter "*bash.exe*").FullName)
}
@("bash.exe", "wsl.exe") | ForEach-Object { Write-Host $((Get-ChildItem C:\Windows\System32\ -Filter $_).FullName) }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "GOOgling eSCeeCeeeM cl13nt"
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * -ErrorAction SilentlyContinue | Select-Object Name, SoftwareVersion
if ($result) { $result }
elseif (Test-Path 'C:\Windows\CCM\SCClient.exe') { Write-Host "SCCM Client found at C:\Windows\CCM\SCClient.exe" -ForegroundColor Cyan }
else { Write-Host "Nowhere to be found" }

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========|| USER INFO"
Write-Host "~Showing which Adm1n5, Us3rs and backup Ops if they are around~"

@("ADMINISTRATORS", "USERS") | ForEach-Object {
  Write-Host $_
  Write-Host "-------"
  Start-Process net -ArgumentList "localgroup $_" -Wait -NoNewWindow
}
Write-Host "BACKUP OPERATORS"
Write-Host "-------"
Start-Process net -ArgumentList 'localgroup "Backup Operators"' -Wait -NoNewWindow


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "Regular person folder ac3ss check"
Get-ChildItem C:\Users\* | ForEach-Object {
  if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor red "Read Access to $($_.FullName)"
  }
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "whosmtamIifnotI"
Write-Host ""
if ($TimeStamp) { TimeElapsed }
Start-Process whoami.exe -ArgumentList "/all" -Wait -NoNewWindow


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Fluffy things in the sky cr3dch3ck~"
$Users = (Get-ChildItem C:\Users).Name
$CCreds = @(".aws\credentials",
  "AppData\Roaming\gcloud\credentials.db",
  "AppData\Roaming\gcloud\legacy_credentials",
  "AppData\Roaming\gcloud\access_tokens.db",
  ".azure\accessTokens.json",
  ".azure\azureProfile.json") 
foreach ($u in $users) {
  $CCreds | ForEach-Object {
    if (Test-Path "c:\$u\$_") { Write-Host "$_ found!" -ForegroundColor Red }
  }
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Application CeeMDee ch3ck.~"
if (Test-Path ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
  Write-Host "$Env:SystemRoot\System32\inetsrv\appcmd.exe exists!" -ForegroundColor Red
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Common Virtual Privrate Network Op3n solution application thing~"

$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs" -ErrorAction SilentlyContinue
if ($Keys) {
  Add-Type -AssemblyName System.Security
  $items = $keys | ForEach-Object { Get-ItemProperty $_.PsPath }
  foreach ($item in $items) {
    $encryptedbytes = $item.'auth-data'
    $entropy = $item.'entropy'
    $entropy = $entropy[0..(($entropy.Length) - 2)]

    $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $encryptedBytes, 
      $entropy, 
      [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
 
    Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
  }
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~~Powersnaill past races"

Write-Host "~PowerSnail races"
Write-Host $(Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String pa)

Write-Host "~Something about app history idk"
Write-Host $(Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-String pa)


Write-Host "~=PowerSnail scripture ch3ck."
if (Test-Path $env:SystemDrive\transcripts\) { "Default transcripts found at $($env:SystemDrive)\transcripts\" }

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Env Vars~"

Get-ChildItem env: | Format-Table -Wrap


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Icky leafpad ch3ck"
if (Test-Path "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite") {
  Write-Host "~icky leafpad pond located. Check it out for plain frogs."
  Write-Host "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite"
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Dragons hoard of things that shouldnt be left around"
cmdkey.exe /list


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "Yeah this one DPAPI is a little RPC Master hard to really change Keys"

$appdataRoaming = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\"
$appdataLocal = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\"
if ( Test-Path "$appdataRoaming\Protect\") {
  Write-Host "found: $appdataRoaming\Protect\"
  Get-ChildItem -Path "$appdataRoaming\Protect\" -Force | ForEach-Object {
    Write-Host $_.FullName
  }
}
if ( Test-Path "$appdataLocal\Protect\") {
  Write-Host "found: $appdataLocal\Protect\"
  Get-ChildItem -Path "$appdataLocal\Protect\" -Force | ForEach-Object {
    Write-Host $_.FullName
  }
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~yeah DPAPI look Cred samefor Master th1s1 Keys"


if ( Test-Path "$appdataRoaming\Credentials\") {
  Get-ChildItem -Path "$appdataRoaming\Credentials\" -Force
}
if ( Test-Path "$appdataLocal\Credentials\") {
  Get-ChildItem -Path "$appdataLocal\Credentials\" -Force
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Frogs currently on the log"
try { quser }catch { Write-Host "'quser' command not not present on system" } 


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~Frogs working from home"
try { qwinsta } catch { Write-Host "'qwinsta' command not present on system" }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~RoastedRibbit t1ck3ts"
try { klist } catch { Write-Host "No active sessions" }


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========|| Printing ClipBoard (if any)"
Get-ClipBoardText

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========|| Unattended Files Check"
@("C:\Windows\sysprep\sysprep.xml",
  "C:\Windows\sysprep\sysprep.inf",
  "C:\Windows\sysprep.inf",
  "C:\Windows\Panther\Unattended.xml",
  "C:\Windows\Panther\Unattend.xml",
  "C:\Windows\Panther\Unattend\Unattend.xml",
  "C:\Windows\Panther\Unattend\Unattended.xml",
  "C:\Windows\System32\Sysprep\unattend.xml",
  "C:\Windows\System32\Sysprep\unattended.xml",
  "C:\unattend.txt",
  "C:\unattend.inf") | ForEach-Object {
  if (Test-Path $_) {
    Write-Host "$_ found."
  }
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========|| SAM / SYSTEM Backup Checks"

@(
  "$Env:windir\repair\SAM",
  "$Env:windir\System32\config\RegBack\SAM",
  "$Env:windir\System32\config\SAM",
  "$Env:windir\repair\system",
  "$Env:windir\System32\config\SYSTEM",
  "$Env:windir\System32\config\RegBack\system") | ForEach-Object {
  if (Test-Path $_ -ErrorAction SilentlyContinue) {
    Write-Host "$_ Found!" -ForegroundColor red
  }
}


Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "~GPP4assw0rdcheck"

$GroupPolicy = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")
if (Test-Path "$env:SystemDrive\Microsoft\Group Policy\history") {
  Get-ChildItem -Recurse -Force "$env:SystemDrive\Microsoft\Group Policy\history" -Include @GroupPolicy
}

if (Test-Path "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" ) {
  Get-ChildItem -Recurse -Force "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
}

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "Sustainable rubbish peak"

Write-Host ""
if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "pw looking"

if ($TimeStamp) { TimeElapsed }
Write-Host -ForegroundColor Blue "pw looking respectfully (takes longer)"
Write-Host -ForegroundColor Blue "pw looking through drivethroughs (Should be quicker)"
$Drives.Root | ForEach-Object {
  $Drive = $_
  Get-ChildItem $Drive -Recurse -Include $fileExtensions -ErrorAction SilentlyContinue -Force | ForEach-Object {
    $path = $_
    if ($Path.FullName -like '*Lang*') {
    }
    else {
      if ($path.Length -gt 0) {
      }
      if ($path -like "*SiteList.xml") {
      }
      $regexSearch.keys | ForEach-Object {
        $passwordFound = Get-Content $path.FullName -ErrorAction SilentlyContinue -Force | Select-String $regexSearch[$_] -Context 1, 1
        if ($passwordFound) {
          Write-Host "We may have located something we shouldnt have: $_" -ForegroundColor Yellow
          Write-Host $Path.FullName
          Write-Host -ForegroundColor Blue "$_ pewpew"
          Write-Host $passwordFound -ForegroundColor Red
        }
      }
    }  
  }
}


Write-Host -ForegroundColor Blue "~Regitrar sometimes writes down things that arent the best"
Write-Host "This could take a hot minute maybe go touch grass"
$regPath = @("registry::\HKEY_CURRENT_USER\", "registry::\HKEY_LOCAL_MACHINE\")
foreach ($r in $regPath) {
(Get-ChildItem -Path $r -Recurse -Force -ErrorAction SilentlyContinue) | ForEach-Object {
    $property = $_.property
    $Name = $_.Name
    $property | ForEach-Object {
      $Prop = $_
      $regexSearch.keys | ForEach-Object {
        $value = $regexSearch[$_]
        if ($Prop | Where-Object { $_ -like $value }) {
          Write-Host "Possible Password Found: $Name\$Prop"
          Write-Host "Key: $_" -ForegroundColor Red
        }
        $Prop | ForEach-Object {   
          $propValue = (Get-ItemProperty "registry::$Name").$_
          if ($propValue | Where-Object { $_ -like $Value }) {
            Write-Host "Possible Password Found: $name\$_ $propValue"
          }
        }
      }
    }
  }
  if ($TimeStamp) { TimeElapsed }
  Write-Host "Finished $r"
}
