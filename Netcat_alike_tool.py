import sys
import socket
import getopt
import threading
import subprocess

# define some global variables
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

def usage():
    print("Netcat_alike_tool")
    print("       <3     ")                            
    print("  ╱|、        ")
    print(" (˚ˎ 。7      ")
    print(" |、˜〵        ") 
    print(" じしˍ,)ノ     ")
    print("")
    print("Usage: netcat.py -t target_host -p port")
    print("-l --listen                     - listen on [host]:[port] for")
    print("                                   incoming connection")
    print("-e --execute=file_to_run       - execute the given file upon")
    print("                                   receiving a connection")
    print("-c --command                    - initialize a command shell")
    print("-u --upload-destination        - upon receiving connection upload a")
    print("                                   file and write to [destination]")
    print()
    print()
    print("Examples: ")
    print("netcat.py -t 192.168.0.1 -p 5555 -l -c")
    print("netcat.py -t 192.168.0.1 -p 5555 -l -u=/tmp/target.exe") # Using /tmp for cross-platform example
    print("netcat.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"")
    print("echo 'ABCDEFGHI' | ./netcat.py -t 192.168.11.12 -p 135")
    sys.exit(0)

def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to the target
        client.connect((target, port))

        if len(buffer):
            client.send(buffer.encode())

        while True:

            # now wait for data back
            recv_len = 1
            response = b""

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data

                if recv_len < 4096:
                    break

            try:
                print(response.decode('utf-8', errors='ignore'), end='')
            except UnicodeDecodeError:
                print(response, end='') # Print raw bytes if decoding fails

            # wait for more input
            buffer = input("")
            buffer += "\n"

            # send it off
            client.send(buffer.encode())

    except socket.error as e:
        print(f"[*] Socket error: {e}")
    except KeyboardInterrupt:
        print("[*] User interrupted.")
    finally:
        print("[*] Closing client.")
        client.close()

def server_loop():
    global target

    # if no target is defined, we listen on all interfaces
    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((target, port))
    except socket.error as e:
        print(f"[*] Binding failed: {e}")
        sys.exit(1)

    server.listen(5)

    print(f"[*] Listening on {target}:{port}")

    while True:
        client_socket, addr = server.accept()

        print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")

        # spin off a thread to handle our new client
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()

def run_command(command):
    command = command.rstrip()

    # run the command and get the output back
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
    except OSError as e:
        output = f"Failed to execute command: {e}\n".encode()
    # Send the output back to the client
    return output

def client_handler(client_socket):
    global upload
    global execute
    global command
    global upload_destination

    # check for upload
    if len(upload_destination):
        # read in all of the bytes and write to our destination
        file_buffer = b""
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            else:
                file_buffer += data

        try:
            with open(upload_destination, "wb") as file_descriptor:
                file_descriptor.write(file_buffer)
            client_socket.send(f"[*] Successfully saved file to {upload_destination}\r\n".encode())
        except Exception as e:
            client_socket.send(f"[*] Failed to save file to {upload_destination}: {e}\r\n".encode())

    # check for command execution
    elif len(execute):
        # run the command
        output = run_command(execute)
        client_socket.send(output)

    # now we go into another loop if a command shell was requested
    elif command:
        while True:
            # show a simple prompt
            client_socket.send(b"<BHP:#> ")
            try:
                # now we receive until we see a linefeed (enter key)
                cmd_buffer = b""
                while b"\n" not in cmd_buffer:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    cmd_buffer += data

                if not cmd_buffer:
                    break # Connection closed by client

                # send back the command output
                response = run_command(cmd_buffer.decode('utf-8', errors='ignore'))

                # Send back the response
                client_socket.send(response)
            except Exception as e:
                print(f"[*] Error in command shell: {e}")
                break
    client_socket.close()

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:",
                                   ["help", "listen", "execute=", "target=", "port=", "command", "upload="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for opt, a in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-l", "--listen"):
            listen = True
        elif opt in ("-e", "--execute"):
            execute = a
        elif opt in ("-c", "--command"):
            command = True
        elif opt in ("-u", "--upload"):
            upload_destination = a
        elif opt in ("-t", "--target"):
            target = a
        elif opt in ("-p", "--port"):
            try:
                port = int(a)
            except ValueError:
                print("[-] Port must be an integer.")
                sys.exit(1)
        else:
            assert False, "Unhandled option"

    # are we going to listen or just send data from stdin?
    if not listen and target and port > 0:
        # read in the buffer from the commandline
        # this will block, so send CTRL-D if not sending input
        # to stdin
        buffer = sys.stdin.read()
        client_sender(buffer)

    if listen:
        server_loop()

if __name__ == "__main__":
    main()
