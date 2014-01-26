simple_kernel
=============

A small, simple kernel example for IPython 1.1

Download and run:

`ipython console --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"`

`ipython notebook --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"`

`ipython qtconsole --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"`

Current status:

* shell, heartbeat, and iopub channels working
* signatures are correct
* need to test control and stdin channels
* need to handle "magics"

Bugs:

1. when running a console, doesn't stop python when exiting

References
----------

These references may be helpful in understanding the big picture of IPython and zmq.

1. http://ipython.org/ipython-doc/rel-1.1.0/development/messaging.html - Messaging documentation
2. http://andrew.gibiansky.com/blog/ipython/ipython-kernels/ - Useful document in making a kernel
3. http://zeromq.github.io/pyzmq/api/index.html - 0MQ Documentation for low-level socket functionality

Other Kernel Examples
---------------------

Here is a list of all of the standalone kernels (backends) that I know about. I don't think I got a single one to run, however.

* https://github.com/gibiansky/IHaskell - Written in Haskell 
* https://github.com/takluyver/igo - Written in Go
 * fails to build, needs Go 1.2?
* https://github.com/mattpap/IScala - Written in Scala
* https://github.com/mattpap/IAldor - Written C
 * fails to build
* https://github.com/mattpap/ipykernel - Written in C
 *  needs "sudo ln -s /usr/lib/x86_64-linux-gnu/libjansson.so.4 /usr/lib/libjansson.so"
 *  needs "sudo apt-get install uuid-dev"
 *  echo fails, needs M_UUID defined
* http://nbviewer.ipython.org/gist/Carreau/4279371/node-kernel.ipynb - Written in JavaScript 
 * needs "sudo apt-get install libzmq-dev"
 * ImportError: The IPython Notebook requires tornado >= 3.1.0, but you have 2.4.1
 * After upgrading "sudo pip install tornado": ImportError: No module named zmq.subprocesskernel
 * Matthias Bussonnier says "The node example pre-date the ability to configure kernelmanager. Just forget about subpricesskernelmanager."
* https://github.com/minrk/profile_jskernel - In-browser JavaScript kernel
 * doesn't work as far as I can tell
* https://bitbucket.org/ipre/calico/src/master/Source/Calico/ZMQServer.cs?at=master - Written in C#, but serves a variety of languages (Java, Python, Scheme, and others)

