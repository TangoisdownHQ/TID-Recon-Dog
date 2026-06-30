export function revealNewAssets(command: string) {

  if (command.includes("cat config.yaml")) {

    return {
      newFiles: ["db_credentials.txt"],
      hint: "Database host: 10.0.0.15"
    }

  }

  if (command.includes("ls /var/www")) {

    return {
      newFiles: ["backup.sql"],
      hint: "backup database found"
    }

  }

  return null
}
