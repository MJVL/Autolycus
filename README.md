# Autolycus

A proof of concept keylogger for the Synergy application/protocol.


## Requirements

* Python >= 3.6
* tshark

## Installation

`python setup.py install`

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