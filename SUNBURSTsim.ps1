Set-StrictMode -Version 2

# In order to present a full simulation, this script will continue to run after determining "SUNBURST will not execute". In reality, subsequent tests will not run
# Workflow reference: https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html

$ComputerSystem = (Get-WmiObject Win32_ComputerSystem)

Write-Output "Domain membership test:"
if ($ComputerSystem.PartofDomain) {
    Write-Output "This computer is a domain member"
} else {
    Write-Output "This computer is not a domain member. SUNBURST will not execute"
}

Write-Output "Domain blocklist test:"

$DomainBlocklist = @( 'swdev.local', 'emea.sales', 'pci.local', 'apac.lab', 'swdev.dmz', 'cork.lab', 'saas.swi', 'dmz.local', `
 'lab.local', 'dev.local', 'lab.rio', 'lab.brno', 'lab.na', 'test', 'solarwinds')

$DNSDomain = "$env:USERDNSDOMAIN"

if ($DomainBlocklist -contains $DNSDomain) {
    Write-Output "Local DNS name $DNSDomain is on SUNBURST Blocklist. SUNBURST will not execute."
} else {
    Write-Output "Local DNS name is not on SUNBURST blocklist and execution may continue."
}

Write-Output "Testing Solarwinds API connectivity:"

if (Test-Connection "api.solarwinds.com" -Quiet) {
    Write-Output "Connectivity tested OK"
} else {
    Write-Output "No connectivity. SUNBURST will not execute"
}

$ServicesKey = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services

Write-Output "Testing services blocklist:"

$ServicesBlocklist = @( 'apimonitor-x64', 'apimonitor-x86', 'autopsy64', `
  'autopsy', 'autoruns64', 'autoruns', 'fsgk32st', 'fswebuid', 'fsgk32', 'fsma32', 'fssm32', 'fnrb32', 'fsaua', `
  'fsorsp', 'fsav32', 'ekrn', 'eguiproxy', 'egui', 'xagt', 'xagtnotif', 'csfalconservice', 'csfalconcontainer', `
  'cavp', 'cb', 'mssense', 'msmpeng', 'windefend', 'sense', 'carbonblack', 'carbonblackk', 'cbcomms', 'cbstream', `
  'csagent', 'csfalconservice', 'xagt', 'fe_avk', 'fekern', 'feelam', 'eamonm', 'eelam', 'ehdrv', 'ekrn', 'ekrnepfw',
  'epfwwfp', 'ekbdflt', 'epfw', 'fsaua', 'fsma', 'fsbts', 'fsni', 'fsvista', 'fses', 'fsfw', 'fsdfw', 'fsaus', 'fsms', 'fsdevcon' )

foreach ($BlockService in $ServicesBlocklist) {

    $found = $ServicesKey | Get-ItemProperty | where { [bool]($_.PSobject.properties["ImagePath"]) -and $_.imagepath -match $BlockService }
    if ($found -and $found.Start -ne 4) {
        Write-Output "Service $BlockService found on this machine. SUNBURST would DISABLE this service and sleep until reboot. Service was NOT DISABLED on this machine."
    }
    if ($found -and $found.Start -eq 4) {
        Write-Output "Service $BlockService found on this machine. SUNBURST would DISABLE this service and sleep until reboot. Service was DISABLED on this machine."
    }
}

Write-Output "Testing driver blocklist:"

$DriversBlocklist = @( 'cybkerneltracker.sys', 'atrsdfw.sys', 'eaw.sys', 'rvsavd.sys', 'dgdmk.sys', 'sentinelmonitor.sys', 'hexisfsmonitor.sys', `
    'groundling32.sys', 'groundling64.sys', 'safe-agent.sys', 'crexecprev.sys', 'psepfilter.sys', 'cve.sys', 'brfilter.sys', 'brcow_x_x_x_x.sys', `
    'lragentmf.sys', 'libwamf.sys')

foreach ($BlockDriver in $DriversBlocklist) {
    $found = $ServicesKey | Get-ItemProperty | where { [bool]($_.PSobject.properties["ImagePath"]) -and $_.imagepath -match $BlockDriver }
    if ($found) {
        Write-Output "Driver $BlockDriver found on this machine. SUNBURST will not execute."
    }
}

Write-Output "Testing process blocklist:"

$ProcessesBlocklist = @('apimonitor-x64', 'apimonitor-x86', 'autopsy64', 'autopsy', 'autoruns64', 'autoruns', 'autorunsc64',`
    'autorunsc', 'binaryninja', 'blacklight', 'cff', 'cutter', 'de4dot', 'debugview', 'diskmon', 'dnsd', 'dnspy', 'dotpeek32',`
    'dotpeek64', 'dumpcap', 'evidence', 'exeinfope', 'fakedns', 'fakenet', 'ffdec', 'fiddler', 'fileinsight', 'floss', 'gdb',`
    'hiew32', 'idaq64', 'idaq', 'idr', 'ildasm', 'ilspy', 'jd-gui', 'lordpe', 'officemalscanner', 'ollydbg', 'pdfstreamdumper',`
    'pe-bear', 'pebrowse64', 'peid', 'pe-sieve32', 'pe-sieve64', 'pestudio', 'peview', 'pexplorer', 'ppee', 'ppee', 'procdump64',`
    'procdump', 'processhacker', 'procexp64', 'procexp', 'procmon', 'prodiscoverbasic', 'py2exedecompiler', 'r2agent', 'rabin2',`
    'radare2', 'ramcapture64', 'ramcapture', 'reflector', 'regmon', 'resourcehacker', 'retdec-ar-extractor', 'retdec-bin2llvmir',`
    'retdec-bin2pat', 'retdec-config', 'retdec-fileinfo', 'retdec-getsig', 'retdec-idr2pat', 'retdec-llvmir2hll', 'retdec-macho-extractor',`
    'retdec-pat2yara', 'retdec-stacofin', 'retdec-unpacker', 'retdec-yarac', 'rundotnetdll', 'sbiesvc', 'scdbg', 'scylla_x64', 'scylla_x86',`
    'shellcode_launcher', 'solarwindsdiagnostics', 'sysmon64', 'sysmon', 'task', 'task', 'tcpdump', 'tcpvcon', 'tcpview', 'vboxservice',`
    'win32_remote', 'win64_remotex64', 'windbg', 'windump', 'winhex64', 'winhex', 'winobj', 'wireshark', 'x32dbg', 'x64dbg', 'xwforensics64',`
    'xwforensics', 'redcloak', 'avgsvc', 'avgui', 'avgsvca', 'avgidsagent', 'avgsvcx', 'avgwdsvcx', 'avgadminclientservice', 'afwserv', 'avastui',`
    'avastsvc', 'aswidsagent', 'aswidsagenta', 'aswengsrv', 'avastavwrapper', 'bccavsvc', 'psanhost', 'psuaservice', 'psuamain', 'avp', 'avpui',`
    'ksde', 'ksdeui', 'tanium', 'taniumclient', 'taniumdetectengine', 'taniumendpointindex', 'taniumtracecli', 'taniumtracewebsocketclient64')

$AllProcesses = Get-Process
foreach ($BlockProcess in $ProcessesBlocklist) {
    $found = $AllProcesses | where { $_.ProcessName -match $BlockProcess }
    if ($found) {
        Write-Output "Process $BlockProcess found on this machine. SUNBURST will not execute."
    }
}