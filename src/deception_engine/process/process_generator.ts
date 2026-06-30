export function generateProcesses(){

return [

{ pid:1, user:"root", cmd:"systemd" },

{ pid:435, user:"root", cmd:"sshd" },

{ pid:821, user:"mysql", cmd:"mysqld" },

{ pid:1023, user:"dev", cmd:"node app.js" },

{ pid:1300, user:"nginx", cmd:"nginx worker" }

]

}
