# enum-groups.ps1
# Produces:
# 1) groups_users.csv  : Group -> Members
# 2) users_groups.csv  : User  -> Groups
# 3) Optional pretty console tables

$ErrorActionPreference = "SilentlyContinue"

function Get-DomainGroupNames {
    # net group /domain output contains lines starting with '*'
    $out = cmd /c 'net group /domain' 2>$null
    $out |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^\*' } |
        ForEach-Object { $_.TrimStart('*').Trim() } |
        Where-Object { $_ -ne "" } |
        Sort-Object -Unique
}

function Get-GroupMembers($groupName) {
    $out = cmd /c "net group `"$groupName`" /domain" 2>$null

    # Members section is after the dashed line under "Members"
    # We'll start collecting after the line of dashes following "Members"
    $members = New-Object System.Collections.Generic.List[string]
    $collect = $false

    foreach ($line in $out) {
        $t = $line.Trim()

        if ($t -match '^Members$') { continue }

        if ($t -match '^-{5,}$') {
            # First dashed line after Members starts collection; the next dashed line doesn't appear,
            # so just flip on once we see the dashes and haven't started yet.
            if (-not $collect) { $collect = $true; continue }
        }

        if ($collect) {
            if ($t -eq "" -or $t -match '^The command completed') { continue }

            # net.exe prints multiple names per line with variable spacing.
            # Split on 2+ spaces to preserve names like First.Last
            $parts = $line -split '\s{2,}' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            foreach ($p in $parts) { $members.Add($p) }
        }
    }

    $members | Sort-Object -Unique
}

# --- Main ---
$groups = Get-DomainGroupNames

# Group -> Users table
$groupUserRows = New-Object System.Collections.Generic.List[object]

# User -> Groups map
$userToGroups = @{}

foreach ($g in $groups) {
    $members = Get-GroupMembers $g

    # Record group->members
    $groupUserRows.Add([pscustomobject]@{
        Group   = $g
        Members = ($members -join ", ")
        Count   = $members.Count
    })

    # Build reverse map user->groups
    foreach ($m in $members) {
        if (-not $userToGroups.ContainsKey($m)) { $userToGroups[$m] = New-Object System.Collections.Generic.List[string] }
        $userToGroups[$m].Add($g)
    }
}

# User -> Groups table
$userGroupRows = New-Object System.Collections.Generic.List[object]
foreach ($u in ($userToGroups.Keys | Sort-Object)) {
    $gs = $userToGroups[$u] | Sort-Object -Unique
    $userGroupRows.Add([pscustomobject]@{
        User   = $u
        Groups = ($gs -join ", ")
        Count  = $gs.Count
    })
}

# Output files (CSV is easiest to exfil + view)
$groupUserRows | Sort-Object Group | Export-Csv -NoTypeInformation -Encoding UTF8 .\groups_users.csv
$userGroupRows | Sort-Object User  | Export-Csv -NoTypeInformation -Encoding UTF8 .\users_groups.csv

# Optional: pretty console view
"`n[Groups -> Users]`n"
$groupUserRows | Sort-Object Count -Descending | Format-Table -AutoSize

"`n[Users -> Groups]`n"
$userGroupRows  | Sort-Object Count -Descending | Format-Table -AutoSize

"`nWrote: groups_users.csv and users_groups.csv`n"
