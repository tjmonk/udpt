# udpt
UDP Template Engine

## Overview

UDPt is a UDP broadcast mechanism which can periodically broadcast
a payload generated from a template file consisting of static text
with embedded varserver variables.

The payload will be broadcast on all available interfaces.  It supports
configuration via varserver variables which can be specified by name
as command line arguments when UDPt is started.

## Template Format

The template used to generate the UDP payload is a basic text file with
embedded varserver variables which will be replaced by their values when
the template is rendered.  The format of a varserver variable reference
in the template is: ${varname}, where varname is the name of the variable.

For example, assuming you have a varserver variable called: "/sys/test/a",
then the following would be a valid UDP broadcast template for a JSON object:

```
{"/sys/test/a":"${/sys/test/a}"}
```

## Invoking the UDPt application

The operation of UDPt is controlled predominantly via varserver variables,
but rather than making the variable names fixed, the calling system
can specify the names of the UDPt configuration parameters via command
line arguments:

The configurations which are controlled via varserver variables are as follows:

    [-v varname] : name of the varserver variable to control verbose output
    [-t varname ] : name of the varserver used to trigger a broadcast
    [-r varname] : name of the varserver variable controlling the transmission
                   rate in seconds.
    [-e varname] : name of the varserver variable which enables (1) or
                   disables (0) the UDP broadcast
    [-i varname ] : name of the varserver variable which contains an list
                    of interfaces on which to broadcast
                    (unspecified/empty = all interfaces)
    [-m varname] : name of the varserver variable which dumps UDPt metrics
    [-a varname] : name of the varserver variable into which UDPt writes the
                   local IP address of the current interface it is broadcasting
                   from
    [-f varname] : name of the varserver variable which contains the path
                   to the UDP template to be rendered and broadcast.

The udpt command can be run with the -h option to display the command usage.

## Example execution

The following command will invoke the UDPt allowing configuration of its
operation:

```
udpt \
-t /sys/udpt/trigger \
-p /sys/udpt/port \
-f /sys/udpt/template  \
-e /sys/udpt/enable \
-m /sys/udpt/metrics \
-i /sys/udpt/interfaces \
-r /sys/udpt/txrate \
-a /sys/udpt/ipaddr
```

If the variables do not exist, they will be created, but UDPt will do
nothing until it is properly configured.  For example:

```
echo -n '{"ip":"${/sys/udpt/ipaddr}"}' > /tmp/template.json
setvar /sys/udpt/enable 1
setvar /sys/udpt/template /tmp/template.json
setvar /sys/udpt/port 20566
setvar /sys/udpt/txrate 1
setvar /sys/udpt/interfaces eth0
```

You can monitor the operation of the UDPt broadcaster using the metrics
variable if you have defined it.

For example, using the metrics defined in our example above you could run:

```
getvar /sys/udpt/metrics
```

You should see something similar to the following:

```
{"enabled": "yes","port": 20566, "txrate": 1, "txcount": 59, "errcount": 0, "interfaces":, "eth0" }
```
