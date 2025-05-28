# Netcat-alike-tool

⠀<pre>
   ／l、
 （ﾟ､ ｡ ７
⠀ l,‏‏‎ ‎‏‏‎ ‎‏‏‎~ヽ
  じしf_, )ノ
 </pre>
A Python-based Netcat clone for versatile network communication. This tool facilitates network debugging, port scanning, and simple data transfer over TCP/UDP, mimicking Netcat's essential command-line functionality.

## Table of Contents

* [Disclaimer](#disclaimer)
* [Features](#features)
    * [Listening Mode](#listening-mode)
    * [Command Execution](#command-execution)
    * [Command Shell](#command-shell)
    * [File Upload](#file-upload)
    * [Client Sender Mode](#client-sender-mode)
* [Usage Examples](#usage-examples)

## Disclaimer

***This tool is intended for educational purposes and legitimate network administration tasks only. Unauthorized use of this tool for illegal activities, such as unauthorized access to computer systems, is strictly prohibited and may result in severe legal consequences. Users are solely responsible for ensuring their actions comply with all applicable laws and regulations.***

## Features

This tool offers several functionalities, allowing for flexible network interactions:

### Listening Mode
The tool can operate as a server, listening on a specified host and port for incoming connections. This is activated with the `-l` or `--listen` flag.

### Command Execution
Upon receiving a connection in listening mode, the tool can execute a specified command or script and send its output back to the connected client. Use the `-e` or `--execute` flag followed by the file or command to run.

### Command Shell
When listening, the tool can initialize a command shell, providing an interactive environment for executing commands on the target system through the established connection. This feature is enabled with the `-c` or `--command` flag.

### File Upload
In listening mode, the tool supports uploading a file from the client and writing it to a specified destination on the server. The `-u` or `--upload-destination` flag is used for this purpose, followed by the desired file path.

### Client Sender Mode
The tool can act as a client, sending data from standard input to a target host and port. This is the default mode when not in listening mode and a target host and port are specified.

## Usage Examples

To display the help menu and available options, run:
`python3 Netcat_alike_tool.py`

* **Listen with a command shell:**
    `python Netcat_alike_tool.py -t 192.168.0.1 -p 5555 -l -c`

* **Listen and upload a file:**
    `python Netcat_alike_tool.py -t 192.168.0.1 -p 5555 -l -u=/tmp/target.exe`

* **Listen and execute a command:**
    `python Netcat_alike_tool.py -t 192.168.0.1 -p 5555 -l -e="cat /etc/passwd"`

* **Send data from stdin to a target:**
    `echo 'ABCDEFGHI' | python Netcat_alike_tool.py -t 192.168.11.12 -p 135`
