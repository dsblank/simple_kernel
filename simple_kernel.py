# simple_kernel.py
# by Doug Blank <doug.blank@gmail.com>
#
# Start with a command, such as:
# ipython console --KernelManager.kernel_cmd="['python', 'simple_kernel.py', 
#                                              '{connection_file}']"

from __future__ import print_function

## Imports:
import sys
import zmq
import atexit
import threading
from zmq.eventloop import ioloop, zmqstream

## Initialize:
print("Loading simple_kernel with args:", sys.argv)
print("Reading config file '%s'..." % sys.argv[1])
config = eval("".join(open(sys.argv[1]).readlines()))
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

exiting = False
def heartbeat_loop():
    while not exiting:
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
    while not exiting:
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

ioloop.install()

# Shell message to handle:
#['<IDS|MSG>', 
# '0ab40204d4c91b42156b1a9610c87bce1d053274953fd3a95030d6610bcbb011', 
# '{"username":"username",
#   "msg_id":"F73E5E6EDD9440A18ECC239325E50C54",
#   "msg_type":"execute_request",
#   "session":"3B80B7712129454695BDEA50440C00B3"}', 
# '{}', 
# '{}', 
# '{"store_history":true,
#   "silent":false,
#   "user_variables":[],
#   "code":"x = 1",
#   "user_expressions":{},
#   "allow_stdin":true}']

# Control message to handle:
# ['\x00\xe4<\x98i', 
#  '<IDS|MSG>', 
#  '47917158f71daf34e9565516a11ea9632aa8a7cd1cfee29fff1c25b9049f373a', 
#  '{"date":"2014-01-18T13:11:04.544653","username":"dblank",
#    "session":"d63aaffb-f40d-492c-ade1-01432181ee3e",
#    "msg_id":"dcc9c54a-d5fb-4570-95a9-4845ad28ebc3",
#    "msg_type":"shutdown_request"}', 
#  '{}', '{}', '{"restart":false}']


def loop(ioloop, name):
    print("Starting loop for '%s'..." % name)
    while True:
        print("%s Loop!" % name)
        try:
            ioloop.start()
        except ZMQError as e:
            print("%s ZMQError!" % name)
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        except Exception:
            print("%s Exception!" % name)
            if exiting:
                break
            else:
                raise
        else:
            print("%s Break!" % name)
            break

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
iopub_socket.bind(iopub_conn)
iopub_loop = ioloop.IOLoop()
iopub_stream = zmqstream.ZMQStream(iopub_socket, iopub_loop)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.ROUTER)
control_socket.setsockopt(zmq.IDENTITY, session_id)
control_socket.bind(control_conn)
control_loop = ioloop.IOLoop()
control_stream = zmqstream.ZMQStream(control_socket, control_loop)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.DEALER)
stdin_socket.setsockopt(zmq.IDENTITY, session_id)
stdin_socket.bind(stdin_conn)
stdin_loop = ioloop.IOLoop()
stdin_stream = zmqstream.ZMQStream(stdin_socket, stdin_loop)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.DEALER)
shell_socket.setsockopt(zmq.IDENTITY, session_id)
shell_socket.bind(shell_conn)
shell_loop = ioloop.IOLoop()
shell_stream = zmqstream.ZMQStream(shell_socket, shell_loop)
shell_stream.on_recv(shell_handler)

print("Starting loops...")
threads = [threading.Thread(target=lambda: loop(shell_loop, "Shell")),
           threading.Thread(target=lambda: loop(iopub_loop, "IOPub")),
           threading.Thread(target=lambda: loop(control_loop, "Control")),
           threading.Thread(target=lambda: loop(stdin_loop, "StdIn")),
           threading.Thread(target=lambda: heartbeat_loop())]
for thread in threads:
    thread.start()
print("Ready! Listening...")
