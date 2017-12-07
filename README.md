# LogicMonitorPOSH
PowerShell module for interacting with LogicMonitor API.
Module under construction - NOT production ready. Use at your own peril. 

Some examples:

* Scheduled DownTime handling:

    * Get-ServiceGroup -sgname 'web-login' | Set-ServiceGroupSDT -comment "down for maintenance" -hours 2
    * Get-LMDeviceGroup -GroupName Exchange | Where fullpath -eq '1. Application/Exchange' | Set-DeviceGroupSDT -comment "Exchange Monthly Reboot"

* Alert handling:

    * Get-LMDevice -computername '*SQL*' | Get-DeviceAlerts
    * Get-SvcAlerts | Get-SvcAlertDetails | Select internalId, monitorObjectName | Send-AlertACK

Remember to fill in PrivateData in module manifest (LogicMonitorAPI.psd1) with your values:

    accessId = '';
    accessKey = '';
    LMAccount = ''
