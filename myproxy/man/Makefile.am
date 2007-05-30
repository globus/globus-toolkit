include $(top_srcdir)/globus_automake_pre

myproxy-logon.1: myproxy-get-delegation.1
	$(LN_S) myproxy-get-delegation.1 myproxy-logon.1


man_MANS = myproxy-admin-adduser.8 \
           myproxy-admin-addservice.8 \
           myproxy-admin-change-pass.8 \
           myproxy-admin-load-credential.8 \
           myproxy-admin-query.8 \
           myproxy-change-pass-phrase.1 \
           myproxy-destroy.1 \
           myproxy-get-delegation.1 \
           myproxy-info.1 \
           myproxy-init.1 \
           myproxy-logon.1 \
           myproxy-replicate.8 \
           myproxy-retrieve.1 \
           myproxy-server.8 \
           myproxy-server.config.5 \
           myproxy-store.1

EXTRA_DIST = $(man_MANS)

include $(top_srcdir)/globus_automake_post
