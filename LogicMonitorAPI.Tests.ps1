$global:here = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.psd1'
Remove-module -Name $sut.Replace('.psd1', '') -Force -ErrorAction Ignore
Import-Module "$here\$sut" -Force -ErrorAction Stop

Describe "LogicMonitorAPI Module unit tests" {

$functions = get-command -Module LogicMonitorAPI
    Foreach ($function in $functions) {
    
        Context "Testing $function Cmdlet" {
        $help = Get-Help $function -full
            It "Is invokable" {
                Invoke-Command {$function.name} | Should Be $function.name
            }
            It "Has comment-based help" {
                $help.description | should not be $null
            }
        }
}
}

Describe "Functional tests" {
    Context "Headers/Authentication tests" {
        $resourcePath = "/service/groups"
        $LMAccount = "$($MyInvocation.MyCommand.Module.PrivateData.LMAccount)"        
        $url = "https://$LMAccount.logicmonitor.com/santaba/rest" + $resourcePath
        $headers = New-Headers -resourcePath $resourcePath -httpVerb 'GET'

        It "Produces valid LMv1 headers" {
            $headers.Authorization | Should match 'LMv1'
        }
        Try {
            $iwr = Invoke-WebRequest -Uri $url -Headers $headers -ErrorAction Stop
        }
        Catch {
            $iwr = $_.Exception.Response.statuscode.Value__
        }
        It "Valid authorization keys" {
            $iwr.StatusCode | should not be 401
        }
    }
    Context "Devices functionality" {
        $devices = Get-LMDevice '*LMON*'
        It "Retrieves devices" {
            $devices.count | Should BeGreaterThan 1
        }
        It "Has collectors" {
            $devices.customProperties.value | Should Match 'collector'
        }
    }
    Context "SDT functionality" {
        $set = Get-LMDevice -Computername 'USALVWDTAPP1' | Set-DeviceSDT -comment "Testing SDT."
        Start-Sleep -Seconds 5      
        $active = Get-ActiveSDT | Where-Object DeviceDisplayName -eq 'USALVWDTAPP1'

        It "Sets SDT" {
            $set | Should Be 'OK'
        }
        It "SDT is on" {
            $active | Should be $true
        }
        It "Clears SDT" {
            Remove-SDT -id $active.id | Should be 'OK'
        }
    }
}