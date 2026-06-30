export type FakeProcess = {
  pid: number
  user: string
  cmd: string
}

export const fakeProcesses: FakeProcess[] = [
  { pid: 1, user: "root", cmd: "systemd" },
  { pid: 435, user: "root", cmd: "sshd" },
  { pid: 821, user: "mysql", cmd: "mysqld" },
  { pid: 1023, user: "dev", cmd: "node app.js" },
]

export function renderProcessTable(): string {
  return fakeProcesses
    .map(p => `${p.user} ${p.pid} ${p.cmd}`)
    .join("\n")
}
