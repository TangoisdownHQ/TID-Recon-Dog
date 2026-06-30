export function bashPrompt(user = "dev"): string {
  return `${user}@dev-server:~$ `
}

export function simulateBashCommand(cmd: string): string {

  if (cmd === "whoami") return "dev"

  if (cmd === "pwd") return "/home/dev"

  if (cmd.startsWith("chmod")) return ""

  if (cmd.startsWith("wget")) return "file downloaded"

  if (cmd.startsWith("curl")) return "HTTP/1.1 200 OK"

  return "command executed"
}
