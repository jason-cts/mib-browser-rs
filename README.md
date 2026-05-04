# known bugs

- SNMPv3 settings is just placeholder; not supported yet
- Go! button is not works due to `active_profile` is not set automatically when create a new device profile from scratch; user have to click profile in the combobox to activate it.

# How to build in Windows (MSVC)

1. install MSVC and Windows SDK from WinGet https://rust-lang.github.io/rustup/installation/windows-msvc.html
2. install Rust and msys2 from https://gist.github.com/KmolYuan/46b2b852c15ac87aa1fc99c7500a5dfc
3. install netsnmp ***x64*** from https://sourceforge.net/projects/net-snmp/files/net-snmp%20binaries/5.5-binaries/
   Note. make sure clicked ***Development files*** and ***Encryption support*** in setup
4. Start -> Search ***x64 Native Tools Command Prompt for VS 2022***
5. append `C:\usr\lib` to LIB and LIBPATH
6. cargo build