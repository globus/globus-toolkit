#! /usr/bin/python

def pre_listen(task_id, transport, attrs):
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "pre_listen":
                raise "pre_listen called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res

def post_listen(task_id, transport, local_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "post_listen":
                raise "post_listen called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res

def pre_accept(task_id, transport, local_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "pre_accept":
                raise "pre_accept called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res


def post_accept(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "post_accept":
                raise "post_accept called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res

def pre_connect(task_id, transport, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "pre_connect":
                raise "pre_connect called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res

def post_connect(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "post_connect":
                raise "post_connect called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res

def pre_close(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "pre_close":
                raise "pre_close called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res

def post_close(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for (scope, name, value) in attrs:
        print "# (%s, %s, %s)" % (scope, name, value)
        if scope == 'python':
            if name == 'test_func' and value != "post_close":
                raise "post_close called when ", value, " expected"
            elif name == 'expected_result':
                print "# evaluating", value
                exec value
    print "# res =", res
    return res
