Run this test by executing TEST.pl

A globus-personal-gatekeeper will be started, a job
will be submitted and a check that everything works
ok will be done.
After the test is done the personal gatekeeper will
be shutdown.

If everything is ok, the test will display "ok"
and the return value is 0

If errors occur, the test will display "failed: <errormessage>"
and the return value is 1

Make sure to configure audit-logging before you run this test.
Read the online documentation (ExecutionManagement -> Pre WS GRAM
-> Admin Guide) for information about audit logging configuration.

