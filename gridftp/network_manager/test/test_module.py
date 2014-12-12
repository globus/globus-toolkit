#! /usr/bin/python

SCOPE = 0
NAME = 1
VALUE = 2

def pre_listen(task_id, transport, attrs):
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "pre_listen":
                raise "pre_listen called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res

def post_listen(task_id, transport, local_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "post_listen":
                raise "post_listen called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res

def pre_accept(task_id, transport, local_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "pre_accept":
                raise "pre_accept called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res


def post_accept(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "post_accept":
                raise "post_accept called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res

def pre_connect(task_id, transport, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "pre_connect":
                raise "pre_connect called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res

def post_connect(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "post_connect":
                raise "post_connect called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res

def pre_close(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "pre_close":
                raise "pre_close called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res

def post_close(task_id, transport, local_contact, remote_contact, attrs):
    print "# task_id =", str(task_id)
    print "# transport =", str(transport)
    print "# local_contact =", str(local_contact)
    print "# remote_contact =", str(remote_contact)
    print "# attrs =", str(attrs)
    res = None
    for attr in attrs:
        print "#", attr
        if attr[SCOPE] == 'python':
            if attr[NAME] == 'test_func' and attr[VALUE] != "post_close":
                raise "post_close called when ", attr[VALUE], " expected"
            elif attr[NAME] == 'expected_result':
                print "# evaluating", attr[VALUE]
                exec attr[VALUE]
    print "# res =", res
    return res
