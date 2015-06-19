nicedaemon
==========

A (daemon) program which is able to change niceness and CPU
affinity of processess based on a set of rules defined in a config
file.

Changing a processes CPU affinity to a single CPU ("sticking" it to
a CPU) can be benefitial for the performance of some 32 bit software (especially
when playing games using wine).

Compiling
---------

```
make
```

Installation
------------

```
make install
```

Configuration
-------------

Make any adjustments you need in /etc/nicedaemon.conf

Features
--------

- Allows matching processes by their command name (/proc/pid/comm) or path.
- Event-driven: nicedaemon *doesn't* need to iterate over all running processes
  to detect new ones.
