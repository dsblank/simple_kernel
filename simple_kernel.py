# simple_kernel.py
# by Doug Blank <doug.blank@gmail.com>
#
# Start with a command, such as:
# ipython console --KernelManager.kernel_cmd="['python', 'simple_kernel.py', 
#                                              '{connection_file}']"

from __future__ import print_function

import sys
import zmq
import atexit
import threading
from zmq.eventloop import ioloop, zmqstream

if len(sys.argv) > 1:
    print("Reading config file '%s'...", sys.argv[1])
    config = eval("".join(open(sys.argv[1]).readlines()))
else:
    # Config is a dictionary/JSON, like:
    config = {
        'stdin_port'      : 36177, 
        'hb_port'         : 50488, 
        'shell_port'      : 47102, 
        'iopub_port'      : 34264, 
        'control_port'    : 49882,
        'signature_scheme': 'hmac-sha256', 
        'key'             : 'c6712346-bf61-4687-beb0-e6dc75b7f885', 
        'ip'              : '127.0.0.1', 
        'transport'       : 'tcp', 
    }
    config = {'stdin_port': 35192, 'hb_port': 49472, 'signature_scheme': 'hmac-sha256', 'key': '1543e795-1d14-4f4e-a9cb-12318be55350', 'ip': '127.0.0.1', 'shell_port': 36538, 'iopub_port': 53231, 'transport': 'tcp', 'control_port': 55809}
print("Config:", config)

connection     = "tcp://" + config["ip"] + ":"
heartbeat_conn = connection + str(config["hb_port"])
iopub_conn     = connection + str(config["iopub_port"])
shell_conn     = connection + str(config["shell_port"])
control_conn   = connection + str(config["control_port"])
stdin_conn     = connection + str(config["stdin_port"])

session_id = unicode(config["key"]).encode("ascii")

def iopub_handler(msg):
    print("iopub received:", msg)

def shell_handler(msg):
    print("shell received:", msg)

def control_handler(msg):
    print("control received:", msg)

def stdin_handler(msg):
    print("stdin received:", msg)

heartbeat_loop_run = True
def heartbeat_loop():
    while heartbeat_loop_run:
        print("Ping!")
        heartbeat_socket.send(b'ping')
        ready = poll()
        if ready:
            heartbeat_socket.recv()
        else:
            print("heartbeat_loop fail!")

def poll():
    events = []
    print("Start poll...")
    while heartbeat_loop_run:
        try:
            print(".", end="")
            sys.stdout.flush()
            events = poller.poll(1000)
        except ZMQError as e:
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        except Exception:
            print("Exception!")
            raise
        #else:
        #    break
    print("Return:", events)
    return events

##########################################
# Heartbeat:
ctx = zmq.Context()
heartbeat_socket = ctx.socket(zmq.REQ)
heartbeat_socket.setsockopt(zmq.LINGER, 0)
heartbeat_socket.connect(heartbeat_conn)
poller = zmq.Poller()
poller.register(heartbeat_socket, zmq.POLLIN)

##########################################
# IOPub/Sub:
# aslo called SubSocketChannel in IPython sources
iopub_socket = ctx.socket(zmq.SUB)
iopub_socket.setsockopt(zmq.SUBSCRIBE,b'')
iopub_socket.setsockopt(zmq.IDENTITY, session_id)
iopub_socket.connect(iopub_conn)
iopub_loop = ioloop.IOLoop()
iopub_stream = zmqstream.ZMQStream(iopub_socket, iopub_loop)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.ROUTER)
control_socket.setsockopt(zmq.IDENTITY, session_id)
control_socket.connect(control_conn)
control_loop = ioloop.IOLoop()
control_stream = zmqstream.ZMQStream(control_socket, control_loop)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.DEALER)
stdin_socket.setsockopt(zmq.IDENTITY, session_id)
stdin_socket.connect(stdin_conn)
stdin_loop = ioloop.IOLoop()
stdin_stream = zmqstream.ZMQStream(stdin_socket, stdin_loop)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.DEALER)
shell_socket.setsockopt(zmq.IDENTITY, session_id)
shell_socket.connect(shell_conn)
shell_loop = ioloop.IOLoop()
shell_stream = zmqstream.ZMQStream(shell_socket, shell_loop)
shell_stream.on_recv(shell_handler)

print("Starting loops...")
threads = [threading.Thread(target=shell_loop.start),
           threading.Thread(target=iopub_loop.start),
           threading.Thread(target=control_loop.start),
           threading.Thread(target=stdin_loop.start),
           threading.Thread(target=heartbeat_loop)]
for thread in threads:
    thread.start()
print("Ready! Listening...")

def stop():
    global heartbeat_loop_run
    shell_loop.stop()
    iopub_loop.stop()
    control_loop.stop()
    stdin_loop.stop()
    heartbeat_loop_run = False
