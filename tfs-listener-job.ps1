param
(
    [Parameter(Mandatory=$true)]
    $SourceVerison,
    [Parameter(Mandatory=$true)]
    $TargetBuildDefinitionName,
    [Parameter(Mandatory=$true)]
    $BranchName,
    [Parameter(Mandatory=$true)]
    $CollectionUrl,
    [Parameter(Mandatory=$true)]
    $TeamProject,
    [Parameter(Mandatory=$true)]
    $GitRepository,
    [Parameter(Mandatory=$true)]
    $Credentials
)

#####################################
#             FUNCTIONS             #
#####################################


function Get-GitPushesByBranch
{
    param
    (
        [Parameter(Mandatory=$true)]
        $BranchName,
        [Parameter(Mandatory=$true)]
        $IncludeRefUpdates="false",
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $GitRepository,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

    try
    {
        $apiVersion = "1.0"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}" -f $Credentials)))
		$requestUrl = "$CollectionUrl/$TeamProject/_apis/git/repositories/$GitRepository/pushes?refName=refs/heads/" + $BranchName + "&includeRefUpdates=$IncludeRefUpdates" + "&api-version=$apiVersion"
        $response = Invoke-RestMethod -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ContentType application/json -Uri $requestUrl
		return $response.value
    }
    
    catch
    {
        Write-Host "Failed retrieve git pushes for branch {$BranchName}, Exception: $_" -ForegroundColor Red
		return $null
    }
}

function Get-CommitsInPush
{
    param
    (
        [Parameter(Mandatory=$true)]
        $PushId,
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $GitRepository,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

    try
    {
        $apiVersion = "1.0"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}" -f $Credentials)))
		$requestUrl = "$CollectionUrl/$TeamProject/_apis/git/repositories/$GitRepository/pushes/$PushId" + "?api-version=$apiVersion"
        $push = Invoke-RestMethod -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ContentType application/json -Uri $requestUrl
        $commitsInPush = $push.commits
		return $commitsInPush
    }
    
    catch
    {
        Write-Host "Failed retrieve git push {$PushId}, Exception: $_" -ForegroundColor Red
		return $null
    }
}

function Get-CommitsByBranch
{
    param
    (
        [Parameter(Mandatory=$true)]
        $BranchName,
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $GitRepository,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

    try
    {
        $apiVersion = "3.0-preview"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}" -f $Credentials)))
		$requestUrl = "$CollectionUrl/$TeamProject/_apis/git/repositories/$GitRepository/commits" + "?api-version=$apiVersion" + "&branch=$BranchName"
        $commits = Invoke-RestMethod -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ContentType application/json -Uri $requestUrl
        $commitsInBranch = $commits.value
		return $commitsInBranch
    }
    
    catch
    {
        Write-Host "Failed retrieve commits from branch {$BranchName}, Exception: $_" -ForegroundColor Red
		return $null
    }
}

function Get-PushIdByCommitId
{
    param
    (
        [Parameter(Mandatory=$true)]
        $BranchName,
        [Parameter(Mandatory=$true)]
        $CommitId,
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $GitRepository,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

    try
    {
        $Pushes = Get-GitPushesByBranch -BranchName "$BranchName" -IncludeRefUpdates "false" -CollectionUrl $CollectionUrl -TeamProject $TeamProject -GitRepository $GitRepository -Credentials $Credentials

        foreach($PushId in ($Pushes | Select pushId).pushId)
        {         
            $CommitsInPush = Get-CommitsInPush -PushId $PushId -CollectionUrl $CollectionUrl -TeamProject $TeamProject -GitRepository $GitRepository -Credentials $Credentials
            
            if(($CommitsInPush | Select commitId).commitId -contains $CommitId)
            { 
                return $PushId
            }
        }

        return $null
    }
    catch
    {
        Write-Host "Failed retrieve pushes that contains commit {$CommitId} in branch {$BranchName}, Exception: $_" -ForegroundColor Red
		return $null
    }
}

function Get-CommitById
{
    param
    (
        [Parameter(Mandatory=$true)]
        $CommitId,
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $GitRepository,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

    try
    {
        $apiVersion = "1.0"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}" -f $Credentials)))
		$requestUrl = "$CollectionUrl/$TeamProject/_apis/git/repositories/$GitRepository/commits/$CommitId" + "?api-version=$apiVersion"
        $response = Invoke-RestMethod -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ContentType application/json -Uri $requestUrl
		return $response
    }
    
    catch
    {
        Write-Host "Failed retrieve the commit {$CommitId}, Exception: $_" -ForegroundColor Red
		return $null
    }
}

function Start-BuildCustomBody
{
    param
    (
        [Parameter(Mandatory=$true)]
        $Body,
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

    try
    {
        $apiVersion = "2.0"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}" -f $Credentials)))
		$requestUrl = "$CollectionUrl/$TeamProject/_apis/build/builds" + "?api-version=$apiVersion"
        $response = Invoke-RestMethod -Method Post -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ContentType application/json -Uri $requestUrl -Body (ConvertTo-Json $Body)
		return $response
    }

    catch
    {
        Write-Host "Failed to trigger build {$BuildDefinitionId}, Exception: $_" -ForegroundColor Red
		return $null
    }
}

function Get-BuildDefinitionId
{
    param
    (
        [Parameter(Mandatory=$true)]
        $BuildDefinitionName,
        [Parameter(Mandatory=$true)]
        $CollectionUrl,
        [Parameter(Mandatory=$true)]
        $TeamProject,
        [Parameter(Mandatory=$true)]
        $Credentials
    )

	try
	{
        $apiVersion = "2.0"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}" -f $Credentials)))
		$requestUrl = "$CollectionUrl/$TeamProject/_apis/build/definitions?name=$BuildDefinitionName" + "&api-version=$apiVersion"
        $response = Invoke-WebRequest -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ContentType application/json -Uri $requestUrl -Method GET -UseBasicParsing
		$buildDefinitionIdJson = $response | ConvertFrom-Json | Select value
		$buildDefinitionId = $buildDefinitionIdJson.value[0].id
		return $buildDefinitionId
	}

	catch
	{
        Write-Host "Failed to get BuildDefinitionId for build {$BuildDefinitionName}, Exception: $_" -ForegroundColor Red
		return $null
	}
}


####################################
#              SCRIPT              #
####################################


# Get the push that contains the "build source version" commit (filtering pushes by branch name)
$PushId = Get-PushIdByCommitId -BranchName $BranchName -CommitId $SourceVerison -CollectionUrl $CollectionUrl -TeamProject $TeamProject -GitRepository $GitRepository -Credentials $Credentials


if($PushId -ne $null)
{
    Write-Host "Commit [$SourceVerison] found in [$PushId]"

    # Retrieve all the commits introduced in the push
    $Commits = Get-CommitsInPush -PushId $PushId -CollectionUrl $CollectionUrl -TeamProject $TeamProject -GitRepository $GitRepository -Credentials $Credentials

    # Get the commit history for the branch
    $CommitsnBranch = (Get-CommitsByBranch -BranchName $BranchName -CollectionUrl $CollectionUrl -TeamProject $TeamProject -GitRepository $GitRepository -Credentials $Credentials).commitId

    # Create a list with all the commits introduced in the push (and its details)
    $CommitsInfo = @()

    # Fill the list with all the commits introduced in the push
    foreach($CommitId in ($Commits | Select commitId).commitId)
    {
        # Filter only the commits for the branch
        if($CommitsnBranch -contains $CommitId)
        {
            $CommitInfo = Get-CommitById -CommitId $CommitId -CollectionUrl $CollectionUrl -TeamProject $TeamProject -GitRepository $GitRepository -Credentials $Credentials
            $CommitsInfo += $CommitInfo
        }
    }


    # Order the commits chronologically
    $CommitsInfo = $CommitsInfo | Select commitId,committer

    foreach($value in $CommitsInfo) 
    { 
        $value.committer = $value.committer.date 
    }

    $OrderedCommits = $CommitsInfo | Sort committer


    # Trigger a build for each commit introduced in the push (chronologically)
    foreach($Commit in $OrderedCommits)
    {
         # Create queue body (build parameters) and trigger build definition
         $CommitSha1 = $Commit.commitId
         $TargetDefinitionId = Get-BuildDefinitionId -BuildDefinitionName $TargetBuildDefinitionName -CollectionUrl $CollectionUrl -TeamProject $TeamProject -Credentials $Credentials
         $QueueBody = @{ definition = @{id = $TargetDefinitionId}; sourceBranch = "refs/heads/$BranchName"; sourceVersion = $CommitSha1 }
         $Response = Start-BuildCustomBody -Body $QueueBody -CollectionUrl $CollectionUrl -TeamProject $TeamProject -Credentials $Credentials
         
         # Print build trigger request response
         if($Response -ne $null)
         {
            $BuildNumber = $Response.buildNumber
            Write-Host "Build [$BuildNumber] successfully trigger from commit [$CommitSha1]"
            Start-Sleep -Seconds 5
         }
         else 
         { 
            Write-Host "Error Triggering build from commit [$CommitSha1]" 
         }
    }
}
else
{
    Write-Host "Commit [$SourceVerison] not found in any push in branch [$BranchName]"
}
