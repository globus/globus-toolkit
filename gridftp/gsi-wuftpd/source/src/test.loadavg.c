#include <stdio.h>

extern int getla(void);

int main(int arc, char **argv)
{
    printf("getla() returned %d\n", getla());
    return (0);
}
