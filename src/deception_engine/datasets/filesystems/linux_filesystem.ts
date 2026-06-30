export const linuxFilesystem = {

"/": ["bin","boot","dev","etc","home","lib","opt","tmp","usr","var"],

"/home": ["admin","dev","backup","ubuntu"],

"/home/admin": [
"deploy.sh",
"notes.txt",
"wallet_keys.json",
"projects",
".ssh"
],

"/home/dev": [
"app.js",
"package.json",
"node_modules",
"logs",
"config.yaml"
],

"/var/log": [
"auth.log",
"syslog",
"kern.log",
"nginx",
"mysql"
],

"/etc": [
"passwd",
"shadow",
"hosts",
"ssh",
"nginx",
"systemd"
],

"/opt": [
"backup",
"scripts",
"monitoring"
]

}
