# Autolycus

A proof of concept keylogger for the Synergy application/protocol.

## Requirements

* Python >= 3.6
* TShark

## Installation

`python setup.py install`

## Docker

Don't feel like installing TShark? Simply build the docker image and then run like so:

`docker run -it a autolycus -h`

Note that you'll need to play around with networking options such that your docker image can sniff on the network/interface of your choice.

## Usage

```
usage: autolycus [-h] [-w num chars] [-k seconds] [-r seconds] [-v level]
                    [-l LOG_FILENAME] [-d]
                    interface

A proof of concept keylogger for the Synergy application/protocol.

positional arguments:
  interface             The interface to listen on.

optional arguments:
  -h, --help            show this help message and exit
  -w num chars, --wrap_limit num chars
                        The max amount of characters to print on a single line when dumping keystrokes/clipboard data.
  -k seconds, --keystroke_wait_time seconds
                        The time in seconds to wait without hearing new keystrokes before printing the dump.
  -r seconds, --redundant_wait_time seconds
                        The time in seconds to wait before printing actions which commonly contain duplicates. Longer window = less duplicates.
  -v level, --verbose level
                        The level of verbosity, with each level adding more. Default = 0.
                        0: keystrokes, clipboards, connection, and screen movement
                        1: mouse clicks
                        2: keep alives, unknowns, and random noisy packets
                        3: mouse movement and NOPs
                        4: any uncaught packets
  -l LOG_FILENAME, --log_filename LOG_FILENAME
                        The filename to log to. Default = YYYYMNDD-HHMMSS
  -d, --disable_logging
                        Prevent logging to a file. Will overwrite -l.
```

## Planned Features
* Cleaning output more reliably upon exit
  * Pyshark has known and unresolved issues related to clean exiting
* MITM proof of concept
* pcap input and output
* Full keyboard support