export type FileTemplate = {
  name: string
  content: string
}

export const linuxRealisticFiles: FileTemplate[] = [
  { name: "deploy.sh", content: "#!/bin/bash\necho Deploying service..." },
  { name: "backup.tar.gz", content: "binary_archive_data" },
  { name: "config.yaml", content: "port: 8080\nenv: production" },
  { name: "notes.txt", content: "Remember to rotate database keys." },
]

export const linuxBaitFiles: FileTemplate[] = [
  { name: "wallet_keys.json", content: '{"wallet":"0x8a23...","key":"abc123"}' },
  { name: "aws_credentials.txt", content: "AWS_ACCESS_KEY_ID=AKIA...\nAWS_SECRET=..." },
  { name: "customer_database.sql", content: "-- simulated database dump" },
]

export const windowsRealisticFiles: FileTemplate[] = [
  { name: "budget.xlsx", content: "binary_excel_data" },
  { name: "client_data.csv", content: "name,email\njohn,john@email.com" },
]

export const windowsBaitFiles: FileTemplate[] = [
  { name: "vpn_credentials.txt", content: "vpnuser: password123" },
  { name: "internal_docs.pdf", content: "binary_pdf_data" },
]
