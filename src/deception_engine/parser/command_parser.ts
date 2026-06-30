export type ParsedCommand = {
  command: string
  args: string[]
}

export function parseCommand(input: string): ParsedCommand {
  const parts = input.trim().split(/\s+/)

  return {
    command: parts[0] || "",
    args: parts.slice(1),
  }
}
