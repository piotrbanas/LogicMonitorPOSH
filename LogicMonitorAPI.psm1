# Module for handling LogicMonitor API
Function New-Headers {
<#
.Synopsis
Construct headers for LogicMonitor REST API.
.DESCRIPTION
Function returns authorisation string for accessing LogicMonitor API.
.PARAMETER resourcepath
Relative URI of the accessed resource
.PARAMETER httpverb
Http method (GET/POST)
.PARAMETER data
Data to post
.EXAMPLE
New-Headers -resourcePath '/service/services' -httpVerb GET
.EXAMPLE
New-Headers -resourcePath "/alert/alerts/$Id/ack" -httpVerb POST -data '{"ackComment":"Starting automated mitigation"}'
.OUTPUTS
System.Collections.Generic.Dictionary[[String],[String]]
.NOTES
Contact: piotrbanas@xper.pl
#>
Param (
    [string]$resourcePath = '/service/services',
    [ValidateSet('GET','POST', 'DELETE')]
    [string]$httpVerb = 'GET',
    [string]$data
)

$accessId = "$($MyInvocation.MyCommand.Module.PrivateData.accessId)"
$accessKey = "$($MyInvocation.MyCommand.Module.PrivateData.accessKey)"
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
# Construct URL #
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath

# Get current time in milliseconds
$epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

# Concatenate Request Details
$requestVars = $httpVerb + $epoch + $data + $resourcePath

# Construct Signature
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
$signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
$signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
$signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

# Construct Headers
$auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization",$auth)
$headers.Add("Content-Type",'application/json')
$headers
}

Function Get-SvcAlerts {
<#
.Synopsis
Retrieve active service alerts.
.DESCRIPTION
Function retrieves active alerts for searched services. 
.PARAMETER servicename
Service name search string
.EXAMPLE
Get-SvcAlerts -servicename "web*" 
#>
[Cmdletbinding()]
Param (
    [string]$ServiceName = "*"
)
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = '/service/services'
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
$headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'

$response = Invoke-RestMethod -Uri $url -Method Get -Header $headers 
$body = $response.data

# Filter active alert, not acknowledged
$body.items | Where-Object {$_.name -like $ServiceName -and $_.AlertStatus -ne 'none'}
}

Function Get-LMDevice  {
<#
.Synopsis
Get LM device
.DESCRIPTION
Based on name, retrieves a LogicMonitor device properties.
.PARAMETER computername
Hostname of the device
.EXAMPLE
#example: Get-LMDevice -computername '*SQL*'
.EXAMPLE
Get-LMDevice -computername 'hostname1', 'hostname2'
.EXAMPLE
get-adcomputer -filter 'name -like "*lmon1"' | Select name | Get-LMDevice
#>
[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$True, Mandatory=$True)]
    [alias("CN","Name")]  
    [string[]]$Computername = "*"
)
BEGIN {
    $LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"    
    $resourcePath = "/device/devices"
    $url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
    $headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'
}
PROCESS {
    Foreach ($computer in $Computername) {
        $filter = "?filter=name~$computer"
        $response = Invoke-RestMethod -Uri ("$url"+"$filter"+'&size=1000') -Method Get -Header $headers 
        $body = $response.data
        $body.items
        }
}
END {}
} #end function

Function Get-LMDeviceGroup  {
    <#
    .Synopsis
    Get LM device group
    .DESCRIPTION
    Based on name, retrieves a LogicMonitor device group properties.
    .PARAMETER GroupName
    Name of the device group
    .EXAMPLE
    Get-LMDeviceGroup -GroupName 'Exchange' | Where fullpath -eq '1. Application/Exchange'
    .EXAMPLE
    .EXAMPLE
    #>
    [Cmdletbinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$True, Mandatory=$True)]
        [alias("Name")]  
        [string[]]$GroupName = "*"
    )
    BEGIN {
        $LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"        
        $resourcePath = "/device/groups"
        $url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
        $headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'
    }
    PROCESS {
        Foreach ($Group in $GRoupName) {
            $filter = "?filter=name~$Group"
            $response = Invoke-RestMethod -Uri ("$url"+"$filter"+'&size=1000') -Method Get -Header $headers 
            $body = $response.data
            $body.items
            }
    }
    END {}
    } #end function

Function Get-DeviceAlerts {
<#
.Synopsis
Get LogicMonitor Device Alerts
.DESCRIPTION
Function retrieves active alerts for a given device
.PARAMETER id
LM device id
.EXAMPLE
Get-DeviceAlerts -id 33
.EXAMPLE
Get-LMDevice -computername '*SQL*' | Get-DeviceAlerts
#>
[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [int]$id
)
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = "/device/devices/$id/alerts"
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
$headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'

$response = Invoke-RestMethod -Uri $url -Method Get -Header $headers 
$body = $response.data

$body.items 
}

Function Get-SvcAlertDetails {
<#
.Synopsis
Retrieve details of the service alert.
.DESCRIPTION
Function retrieves alert details for a given service top-level alert.
.PARAMETER id
Id of the failing service.
.EXAMPLE
Get-SvcAlertDetails -id 55
.EXAMPLE
Get-SvcAlerts | Get-SvcAlertDetails
.OUTPUTS
System.Management.Automation.PSCustomObject
.NOTES
Contact: piotrbanas@xper.pl
#>
[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [int[]]$id
)
BEGIN {
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
}
PROCESS {
    $resourcePath = "/service/services/$id/alerts"
    $url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
    $headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'

    $response = Invoke-RestMethod -Uri $url -Method Get -Header $headers 
    $body = $response.data
    $body.items
}
}

Function Send-AlertACK {
<#
.Synopsis
Acknowledge the alert.
.DESCRIPTION
Sends ack and comment for the alert specified.
.PARAMETER internalId
Id of the alert.
.EXAMPLE
Send-AlertACK -internalID LMS23456789 -comment "Staring mitigation"
.EXAMPLE
Get-SvcAlerts | Get-SvcAlertDetails | Select internalId, monitorObjectName | Send-AlertACK
.OUTPUTS
System.String (errmsg)
.NOTES
Contact: piotrbanas@xper.pl
#>
[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string[]]$internalId,
    [string]$comment = "Alert acknowledged by Orchestrator"
)
BEGIN {
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
}
PROCESS {
$resourcePath = "/alert/alerts/$internalId/ack"
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath

$data = @"
{"ackComment":"$comment"}
"@

$headers = New-Headers -resourcePath $resourcePath -httpVerb 'POST' -data $data

$response = Invoke-RestMethod -Uri $url -Method POST -Header $headers -Body $data
$response.errmsg
}
}

Function Update-AlertNote {
<#
.Synopsis
Update alert note
.DESCRIPTION
Udate note of the LogicMonitor ongoing alert
.PARAMETER internalId
Id of the alert
.PARAMETER comment
Note that we are adding to the alert
.EXAMPLE
Update-AlertNote -internalId 33 -comment "New Note"
.EXAMPLE
Get-SvcAlerts -ServiceName "App1-Web*" | Get-SvcAlertDetails | Where {$_.instancename -eq 'website-overall' -and !$_.SDT}} | Update-AlertNote -internalId $_.id -comment "New note" 
#>
[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string[]]$internalId,
    [string]$comment = "Alert updated by Orchestrator"
)
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = "/alert/alerts/$internalId/note"
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath

$data = @"
{"ackComment":"$comment"}
"@

$headers = New-Headers -resourcePath $resourcePath -httpVerb 'POST' -data $data
$response = Invoke-RestMethod -Uri $url -Method POST -Header $headers -Body $data
$response.errmsg    
}

Function Get-ServiceGroup {
<#
.Synopsis
Get service group
.DESCRIPTION
Retrieve LogicMonitor service group
.PARAMETER sgname
Service group name or search string
.EXAMPLE
Get-ServiceGroup -sgname 'web-login' | Set-ServiceGroupSDT
#>
Param (
    $sgname = "*"
)
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = "/service/groups"
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
$headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'

$response = Invoke-RestMethod -Uri $url -Method Get -Header $headers 
$response.data.items | Where-Object name -like $sgname
}

Function Set-ServiceGroupSDT {
<#
.Synopsis
Set Service Group SDT
.DESCRIPTION
Sets Scheduled Down Time for a given service group in LogicMonitor.
.PARAMETER id
Id of the service group
.PARAMETER name
Name of the service group
.PARAMETER comment
Comment to attach to SDT
.PARAMETER hours
Number of hours that the SDT will be in effect
.EXAMPLE
Set-ServiceGroupSDT -id 23 -name 'web-login' -comment "down for maintenance" -hours 1
.EXAMPLE
Get-ServiceGroup -sgname 'web-login' | Set-ServiceGroupSDT -comment "down for maintenance"
.OUTPUTS
System.String (errmsg)
.NOTES
Contact: piotrbanas@xper.pl
#>

[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [int]$Id,
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    [string]$comment = "ServiceGroup down for maintenance",
    [int]$hours = 1
)
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = '/sdt/sdts'
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
$startDateTime = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
$endDateTime = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ((Get-Date).AddHours($hours)).ToUniversalTime()).TotalMilliseconds)


$data = @"
{"comment":"$comment",
"sdtType":1,
"type":"ServiceGroupSDT",
"serviceGroupId":"$ID",
"serviceGroupName":"$Name",
"startDateTime":"$startDateTime",
"endDateTime":"$endDateTime"
}
"@

$headers = New-Headers -resourcePath $resourcePath -httpVerb 'POST' -data $data

$response = Invoke-RestMethod -Uri $url -Method POST -Header $headers -Body $data
$response.errmsg
}

Function Set-DeviceGroupSDT {
    <#
    .Synopsis
    Set Device Group SDT
    .DESCRIPTION
    Sets Scheduled Down Time for a given device group in LogicMonitor.
    .PARAMETER Id
    Id of the device group
    .PARAMETER FullPath
    Path of the device group
    .PARAMETER comment
    Comment to attach to SDT
    .PARAMETER hours
    Number of hours that the SDT will be in effect
    .EXAMPLE
    .EXAMPLE
    .OUTPUTS
    System.String (errmsg)
    .NOTES
    Contact: piotrbanas@xper.pl
    #>
    
    [Cmdletbinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [int]$Id,
        [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$FullPath,
        [string]$comment = "Device Group down for maintenance",
        [int]$hours = 1
    )
    $LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"    
    $resourcePath = '/sdt/sdts'
    $url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
    $startDateTime = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
    $endDateTime = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ((Get-Date).AddHours($hours)).ToUniversalTime()).TotalMilliseconds)
    
    
$data = @"
{"comment":"$comment",
"sdtType":1,
"type":"DeviceGroupSDT",
"deviceGroupId":"$Id",
"deviceGroupFullPath":"$FullPath",
"dataSourceId":0,
"dataSourceName":"All",
"startDateTime":"$startDateTime",
"endDateTime":"$endDateTime"
}
"@
    
    $headers = New-Headers -resourcePath $resourcePath -httpVerb 'POST' -data $data
    
    $response = Invoke-RestMethod -Uri $url -Method POST -Header $headers -Body $data
    $response.errmsg

}

Function Set-DeviceSDT {
<#
.Synopsis
Set Device SDT
.DESCRIPTION
Sets Scheduled Down Time for a given device in LogicMonitor.
.PARAMETER id
Id of the device
.PARAMETER name
Name of the device
.PARAMETER comment
Comment to attach to SDT
.PARAMETER hours
Number of hours that the SDT will be in effect
.EXAMPLE
Set-DeviceSDT -id 23 -name 'hostname1' -comment "down for maintenance" -hours 1
.EXAMPLE
Get-LMDevice -computername 'hostname1' | Set-DeviceSDT -comment "down for maintenance"
.OUTPUTS
System.String (errmsg)
.NOTES
Contact: piotrbanas@xper.pl
#>

[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [int]$Id,
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,
    [string]$comment = "Device down for maintenance. SDT added by $env:USERNAME",
    [int]$hours = 1
)
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = '/sdt/sdts'
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
$startDateTime = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
$endDateTime = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end ((Get-Date).AddHours($hours)).ToUniversalTime()).TotalMilliseconds)

$data = @"
{"comment":"$comment",
"sdtType":1,
"type":"DeviceSDT",
"DeviceId":612,
"deviceDisplayName":"$displayname",
"startDateTime":"$startDateTime",
"endDateTime":"$endDateTime"
}
"@

$headers = New-Headers -resourcePath $resourcePath -httpVerb 'POST' -data $data

$response = Invoke-RestMethod -Uri $url -Method POST -Header $headers -Body $data
$response.errmsg
}

Function Get-ActiveSDT {
<#
.Synopsis
Get LogicMonitor SDT
.DESCRIPTION
Retrieve active Scheduled Down Times
.EXAMPLE
Get-ActiveSDT | Where-Object ServiceGroupName -eq 'web-login' | Delete-SDT
#>
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
$resourcePath = '/sdt/sdts'
$url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
$headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'

$response = Invoke-RestMethod -Uri $url -Method GET -Header $headers
$response.data.items
}
Function Remove-SDT {
<#
.Synopsis
Remove Logic Monitor SDT
.DESCRIPTION
Remove Scheduled Down Time
.PARAMETER Id
Id of LogicMonitor SDT
.EXAMPLE
Get-ActiveSDT | Where-Object ServiceGroupName -eq 'web-login' | Delete-SDT
#>
[Cmdletbinding()]
Param (
    [Parameter(ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Id
)
BEGIN {
$LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"
}
PROCESS {
    $resourcePath = "/sdt/sdts/$id"
    $url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
    $headers = New-Headers -resourcePath $resourcePath -httpVerb 'DELETE'

    $response = Invoke-RestMethod -Uri $url -Method Delete -Header $headers
    $response.errmsg
}
}
