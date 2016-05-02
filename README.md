# opendec
OpenDec is tending to be used disassemble or decompile the binary file. It furthermore allows you to decompile binary files into a high-level language representation, such as C, Python. It has only support for Python3 (GDB compiled with Python3 support).
For lists the symbols of executable file it uses pyelftools. 

Install pyelftools:
``` 
$ pip3 install pyelftools
```

#### Options

```
(gdb)  dec -h
Usage: dec (sel|arch|fformat|endian|hhl|key)


Options:
  -h, --help            show this help message and exit
  -s SELECTIVE, --sel=SELECTIVE
                        Selective decompile
  -a ARCHITECTURE, --arch=ARCHITECTURE
                        Architecture
  -e ENDIAN, --end=ENDIAN
                        Endianness
  -l HIGHL, --hhl=HIGHL
                        High-level language
  -k APIKEY, --key=APIKEY
                        API KEY
  -f SYMBOLS, --symbols=SYMBOLS
                        List symbols

```

##### The meanings of commands

| option        | description   |
| ------------- |:-------------:|
| selective     | When given, only the selected functions will be decompiled. |
| architecture      | Instructions for which architecture does the machine code contain?      |
| endian | Endianness of the machine code      |
| highl  | Type of the target high-level language.|
| apikey | API Key |
| symbols | List of symbols |


###Links:
https://retdec.com/api/docs/decompiler.html
