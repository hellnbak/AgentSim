// CrowdStrike Falcon LogScale / Next-Gen SIEM
// High-velocity discovery commands launched by the same Python parent.
// Select a short search window and tune the parent allowlist before alerting.
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(python(w)?(3(\.\d+)?)?(\.exe)?|py\.exe)$/i
| CommandLine=/(?<DiscoveryCommand>\bwhoami\b|\bsysteminfo\b|\bhostname\b|\buname\s+-a\b|\bsw_vers\b|\bsystem_profiler\b|\bnet\s+user\b|\bget-localuser\b|\bdscl\s+\.\s+list\s+\/users\b|\bgetent\s+passwd\b|\bcat\s+\/etc\/passwd\b|\btasklist\b|\bwmic\s+process\b|\bget-process\b|\bps\s+aux\b|\btop\s+-(bn|l)\b|\bnetstat\b|\bget-nettcpconnection\b|\bss\s+-tulpn\b|\bipconfig\b|\bifconfig\b|\bip\s+address\s+show\b|\barp\s+-a\b|\bnetworksetup\b|\baws\s+(sts|ec2)\b|\baz\s+resource\s+list\b|\bgcloud\s+services\s+list\b)/i
| bucket(
    span=5s,
    field=[aid, ComputerName, ParentProcessId, ParentBaseFileName],
    function=[
        count(DiscoveryCommand, distinct=true, as=DistinctDiscoveryCommands),
        count(as=Executions),
        collect([ImageFileName, CommandLine])
    ],
    limit=max
  )
| DistinctDiscoveryCommands >= 4
| sort(DistinctDiscoveryCommands, order=desc, limit=200)
