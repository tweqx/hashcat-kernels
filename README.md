
New kernels for hashcat (> 6.0.0)

## Supported modes
* BLAKE2b-512($salt.$pass)

## Installation

### On Linux
- Download the [latest release](https://github.com/tweqx/hashcat-kernels/releases/).
- Locate where hashcat is installed (for instance, `/usr/local/share/hashcat`)
- Extract all `m90000_*` files of the archive to `<hashcat install dir>/OpenCL/`
- Copy `module_90000.so` to `<hashcat install dir>/modules/`

### On Windows
- Download the [latest release](https://github.com/tweqx/hashcat-kernels/releases/)
- Locate where hashcat is installed
- Extract all `m90000_*` files of the archive to `<hashcat install dir>\OpenCL\`
- Extract `module_90000.dll` in `<hashcat install dir>\modules\`

## License
MIT

