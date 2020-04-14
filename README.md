# ProfileGenerator
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

An automated solution to generate profile for memory forensic and virtual machine introspection    
### Still in development    
* The current version is an initial prototype with basic functionalities. 
* Need to come up with a better name

## Getting started

### Prerequisites

* Linux-amd64 (Tested on Ubuntu 16.04)    
* [SWI-prolog](https://www.swi-prolog.org/): `$ sudo apt-get install swi-prolog`

* [PySwip](https://github.com/yuce/pyswip.git): `$ pip install pyswip`

### Installing
`$ git clone https://github.com/enlighten5/ProfileGenerator.git` and ready to go

## Running the test

### Test image

This tool is tested on several Debian and Ubuntu systems, with Linux kernel from 2.6 to 4.10. 

One test image (Ubuntu 16.04 LTS) can be found here:     
`$ wget https://cluster.hpcc.ucr.edu/~zqi020/image/lubuntu_x64.bin` 

### Run it    
`$ cd prolog_engine`    
`$ python prolog_query.py /PATH/TO/TEST/IMAGE /PATH/TO/SYSTEM.MAP`    
* Currently it identifies offsets for some fields in `task_struct`, e.g. `tasks`, `mm_struct`, `comm`, `parent`, etc.

* For the current implementation, it requires the System.map file to compute the KASLR shift and address of init_task.

* The program times out after 10 minutes and saves the generated profile. Then it can be exited by `Ctrl-c`

## Features    
* Auto-locate kernel page table. 
* Resilient against KASLR
* Auto-generate profiles directly from raw memory dumps    
## License    
This project is under the GPLv3 license. See [LICENSE](LICENSE) for details

## Acknowledgment    
* Some of the functions are from Volatility: https://github.com/volatilityfoundation/volatility.git    
* SWI-prolog: https://www.swi-prolog.org/
* PySwip: https://github.com/yuce/pyswip.git
* Hat tip to anyone whose code was used.

