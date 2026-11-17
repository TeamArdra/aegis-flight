"""Send one rewrite-mode command to px_fc_proxy.py's loopback control port (ctl port = data port + 1). Run ON THE PI
(or invoked there over ssh from the laptop campaign driver, which has no route to the Pi's loopback otherwise).
usage: px_proxy_ctl.py DATA_PORT alt_bias 40 | batt_jump 3 | freeze | heading 90 | off"""

import socket
import sys

ctl_port = int(sys.argv[1]) + 1
cmd = " ".join(sys.argv[2:])
c = socket.create_connection(("127.0.0.1", ctl_port), timeout=3)
c.sendall(cmd.encode())
print(c.recv(10).decode().strip())
