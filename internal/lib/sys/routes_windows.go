package sys

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

func ConfigureWindowsRoutes(tunName string, serverIP string, tunIP string, tunGateway string, tunPrefix int) error {
	log.Printf("[INFO] === Windows TUN routing setup for %s ===", tunName)

	var (
		cmd    *exec.Cmd
		output []byte
		err    error
	)

	var subnetMaskStr string
	switch tunPrefix {
	case 30:
		subnetMaskStr = "255.255.255.252"
	case 24:
		subnetMaskStr = "255.255.255.0"
	case 16:
		subnetMaskStr = "255.255.0.0"
	case 8:
		subnetMaskStr = "255.0.0.0"
	default:
		mask := uint32(0xFFFFFFFF << uint(32-tunPrefix))
		subnetMaskStr = fmt.Sprintf("%d.%d.%d.%d",
			byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
	}

	psAutoRouting := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
try {
  Start-Sleep -Milliseconds 800

  $adapter = Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like "*Meta Tunnel*" -or
    $_.InterfaceDescription -like "*Whispera VPN*" -or
    $_.InterfaceDescription -like "*wintun*" -or
    $_.Name -eq "%[1]s" -or
    $_.Name -eq "Whispera"
  } | Sort-Object ifIndex | Select-Object -First 1

  if (-not $adapter) {
    Write-Output "ADAPTER_NOT_FOUND"
    exit 1
  }

  $alias = $adapter.Name
  Write-Output ("[PS-AUTO] Using adapter: " + $alias)

  try {
    $profile = Get-NetConnectionProfile -InterfaceAlias $alias -ErrorAction SilentlyContinue
    if ($profile) {
      Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Private -Name "Whispera" -ErrorAction SilentlyContinue
      Write-Output "[PS-AUTO] Connection profile set to 'Whispera'"
    }
  } catch {}

  try {
    $fwRuleName = "Whispera Inbound Allow"
    Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $fwRuleName -InterfaceAlias $alias -Direction Inbound -Action Allow -Profile Any -Protocol Any -ErrorAction SilentlyContinue | Out-Null
    Write-Output "[PS-AUTO] Firewall rule created"
  } catch {}

  Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

  netsh interface ipv4 set address name="$alias" static %[2]s %[3]s %[4]s 1 | Out-Null
  Start-Sleep -Milliseconds 300
  
  try {
    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses "%[4]s" -ErrorAction Stop | Out-Null
    Write-Output "[PS-AUTO] DNS server set to %[4]s"
  } catch {}

  try {
    Set-NetIPInterface -InterfaceAlias $alias -InterfaceMetric 1 -MTU 1400 -ErrorAction Stop | Out-Null
  } catch {}
  
  Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq "%[4]s" } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

  Get-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Get-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

  $gwRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.NextHop -ne "%[4]s" -and $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric | Select-Object -First 1

  $defaultGW = $null
  if ($gwRoute) {
    $defaultGW = $gwRoute.NextHop
  } else {
    $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
    if ($cfg -and $cfg.IPv4DefaultGateway) {
      $defaultGW = $cfg.IPv4DefaultGateway.NextHop
    }
  }

  if ("%[5]s" -ne "" -and $defaultGW) {
    New-NetRoute -DestinationPrefix "%[5]s/32" -NextHop $defaultGW -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
  }

  New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $alias -NextHop %[4]s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
  New-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $alias -NextHop %[4]s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
  
  Write-Output "SUCCESS"
} catch {
  Write-Output ("[PS-AUTO] ERROR: " + $_.Exception.Message)
  exit 1
}
`, tunName, tunIP, subnetMaskStr, tunGateway, serverIP)

	cmd = exec.CommandContext(context.Background(), "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psAutoRouting)
	output, err = cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err == nil && strings.Contains(outStr, "SUCCESS") {
		log.Printf("[INFO] PowerShell auto-routing completed successfully")
		time.Sleep(500 * time.Millisecond)
		return nil
	}

	log.Printf("[WARN] PowerShell routing failed: %v, output: %s. Using legacy fallback...", err, outStr)

	quotedName := fmt.Sprintf("name=%q", tunName)
	cmd = exec.CommandContext(context.Background(), "netsh", "interface", "ipv4", "set", "address",
		quotedName, "static", tunIP, subnetMaskStr)
	cmd.Run()
	if err != nil {
		return fmt.Errorf("setup failed: %s", outStr)
	}

	return nil
}

func CleanupWindowsRoutes(tunName string, serverIP string, tunGateway string) error {
	log.Printf("[INFO] === Windows TUN routing cleanup for %s ===", tunName)

	prefixes := []string{"0.0.0.0/1", "128.0.0.0/1"}
	for _, p := range prefixes {
		psDelRoute := fmt.Sprintf(`Get-NetRoute -DestinationPrefix "%s" -InterfaceAlias "%s" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, p, tunName)
		_ = exec.CommandContext(context.Background(), "powershell", "-Command", psDelRoute).Run()
	}

	if serverIP != "" {
		psDelHost := fmt.Sprintf(`Get-NetRoute -DestinationPrefix "%s/32" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, serverIP)
		_ = exec.CommandContext(context.Background(), "powershell", "-Command", psDelHost).Run()
	}

	psResetDNS := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ResetServerAddresses -ErrorAction SilentlyContinue`, tunName)
	_ = exec.CommandContext(context.Background(), "powershell", "-Command", psResetDNS).Run()

	return nil
}
