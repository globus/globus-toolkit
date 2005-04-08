include $(top_srcdir)/globus_automake_pre

myproxy-logon.1: myproxy-get-delegation.1
	$(LN_S) myproxy-get-delegation.1 myproxy-logon.1


man_MANS = myproxy-destroy.1 myproxy-get-delegation.1 myproxy-logon.1 \
           myproxy-info.1 \
           myproxy-init.1 myproxy-server.config.5 \
           myproxy-admin-load-credential.8 \
           myproxy-admin-query.8 myproxy-server.8

EXTRA_DIST = $(man_MANS)

include $(top_srcdir)/globus_automake_post
