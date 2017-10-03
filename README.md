Puny Websocket
===============

The weakest websocket client around!

# Build

Compile with standard autoconf/automake combo.

```
autoconf && ./configure && make
```

# Usage

Connect the client to a listening webserver via the following:

## Non-SSL Endpoint on port 80 at example.com/

```
./build/bin/puny-ws example.com
```

## SSL Based Endpoint on port 443 at example.com/some/resource

```
./build/bin/puny-ws --ssl --port 443 --path '/some/resource' example.com
```

You should be able to watch any websocket events directly in your CLI.

# Copyright

Matthew Carter <m@ahungry.com>

# License

GPLv3 or later
