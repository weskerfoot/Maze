## What is this?

A set of D bindings for liblxc, as well as an abstraction layer around the library. It is also aiming to have a web frontend for managing your LXC containers, and if I get really ambitious, a system for sharing file descriptors between containers using Unix Domain Sockets (i.e. [Capability Based Security](https://en.wikipedia.org/wiki/Capability-based_security), as well as default security settings to prevent the containers from open-ing any file descriptors outside of itself.
