simple_kernel
=============

A small, simple kernel example for IPython

Current status:

* sockets are now receiving data
* signatures are now correct
* no luck in sending a result yet

Other Kernel Examples
---------------------

* http://andrew.gibiansky.com/blog/ipython/ipython-kernels/ - Useful document in making a kernel
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
 * Maybe it is written for IPython 1.1?

References
----------

1. http://ipython.org/ipython-doc/rel-1.1.0/development/messaging.html
