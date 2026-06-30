export type MachineState = {
  cwd: string
  installedPrograms: string[]
  createdFiles: string[]
  persistence: string[]
}

export function createMachineState(): MachineState {
  return {
    cwd: "/",
    installedPrograms: [],
    createdFiles: [],
    persistence: [],
  }
}
