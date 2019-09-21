import std.stdio;
import lxc;

class LXCException : Exception {
  this(string msg,
       string file = __FILE__,
       size_t line = __LINE__) {
        super(msg, file, line);
    }
}

class Container {
  lxc_container *container;

  this(string name) {
    this.container = lxc_container_new(name.ptr, null);
    if (!this.container) {
      throw new LXCException("Failed to create LXC container");
    }

    if (this.container.is_defined(this.container)) {
      throw new LXCException("LXC container already exists");
    }

    /* Create the container */
    if (!this.container.createl(this.container,
                                "download".ptr,
                                null,
                                null,
                                LXC_CREATE_QUIET,
                                "-d".ptr,
                                "ubuntu".ptr,
                                "-r".ptr,
                                "trusty".ptr,
                                "-a".ptr,
                                "i386".ptr,
                                null)) {

        throw new LXCException("Failed to create container rootfs");
    }
  }

  void
  startContainer() {
    /* Start the container */
    if (!this.container.start(this.container, 0, null)) {
      throw new LXCException("Failed to start the container");
    }
  }

  void
  stopContainer() {
    /* Stop the container */
    if (!this.container.shutdown(this.container, 30)) {
      stderr.writeln("Failed to cleanly shutdown the container, forcing.");
      if (!this.container.stop(this.container)) {
        throw new LXCException("Failed to kill the container");
      }
    }
  }

  void
  destroyContainer() {
    /* Destroy the container */
    if (!this.container.destroy(this.container)) {
      throw new LXCException("Failed to destroy the container");
    }
  }

  ~this() {
    /* Drops the reference to the container on destruction */
    lxc_container_put(this.container);
  }
}

int
test()
{
  int r = 1;

  auto c = new Container("apicontainer");

  writeln("Container state: ", c.container.state(c.container));
  writeln("Container PID:", c.container.init_pid(c.container));
  writeln(c.container.configfile);

  c.destroyContainer();

  const char*[] args = ["-d".ptr, "ubuntu".ptr, "-r".ptr, "trusty".ptr, "-a", "i386".ptr];

  return r;
}

void
main()
{
  test();
}
