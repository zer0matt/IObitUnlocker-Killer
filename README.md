# IObitUnlocker-Killer
IObitUnlocker ships a .sys driver that allows you to kill any process (except for a little whitelist hardcoded into the driver itself) with Kernel-level privileges.

This is NOT a security vulnerability since no boundary has been crossed (it goes straight from admin to kernel).

Driver: IObitUnlocker.sys (SHA256: c6e50ac7b540e20979b9928867bacf738fab41e0543b0587cd8c0fe90273a577)

<video src="demo.mp4" controls loop autoplay muted width="600"></video>

### Build
```
cl.exe poc_iobitunlocker.c /Fe:poc_iobitunlocker.exe
```
### Run
Just give this once:
```
python3 patch_checksum.py poc_iobitunlocker.exe
```

And finally when you're ready to run it:
```
.\poc_iobitunlocker.exe --pid XXXX
```
