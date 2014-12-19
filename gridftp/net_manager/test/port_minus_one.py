def pre_listen(task_id, transport, attr_array):
    new_attrs = []
    for (scope, name, value) in attr_array:
        if scope == transport and name == 'port':
            value = str(int(value) - 1)
        new_attr = (scope, name, value)
        new_attrs.append(new_attr)
    return new_attrs
