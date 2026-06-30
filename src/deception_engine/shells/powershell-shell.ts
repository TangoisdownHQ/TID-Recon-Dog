export function powershellPrompt(): string {
  return "PS C:\\Users\\Administrator> "
}

export function simulatePowerShell(cmd: string): string {

  if (cmd.includes("Get-Process")) {
    return `
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  ProcessName
-------  ------    -----      -----     ------     --  -----------
200      12        30000      45000     1.23       432  explorer
150      10        20000      35000     0.50       800  svchost
`
  }

  if (cmd.includes("whoami")) {
    return "DESKTOP\\Administrator"
  }

  return "command completed"
}
