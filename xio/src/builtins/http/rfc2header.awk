#! /usr/bin/awk -f 
BEGIN {
    newpage=1;
    print "static"
    print "const char *"
    print "globus_l_http_descriptions[] = {"
}
/\[Page [0-9]+\]/ { next }
/^$/ {
    next;
}
newpage && /^RFC/ {
    newpage=0;
    next;
}
/^$/ {
    newpage=1
    next;
}
/Status-Code *=/ {
    print_now=1;
    first=1
    next;
}

print_now && /extension-code/ {
    print_now=0;
    next;
}

print_now && /"[0-9][0-9][0-9]"/ {
    if (first) {
        first=0;
    } else {
        print ","
    }
    numstr=substr($0, index($0, "\"")+1);
    number=substr(numstr, 0, index(numstr, "\"")-1);
    description=substr($0, index($0, ":")+2);
    printf("    \"%s\", \"%s\"", number, description);
}
END {
    printf("\n};\n");
}
