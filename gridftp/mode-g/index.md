Globus XIO Mode G Drivers {#mainpage}
=========================

- [Mode G Connection Driver](connection_driver.html)
  This driver is a low level implementation of the Mode G data connection
  protocol. It maps the Mode G data protocol to Globus XIO data descriptors
  and creates and parses message headers, ensuring that the protocol
  is followed correctly. Each XIO handle represents a single data connection,
  upon which the driver may process multiple data flows.
- [Mode G Transfer Driver](transfer_driver.html):
  This driver is a transfer-oriented driver built on the Mode G Connection
  Driver. It multiplexes data transfer operations across a pool of Mode G
  Connection handles. Each XIO handle for this driver represents a single
  data transfer.
