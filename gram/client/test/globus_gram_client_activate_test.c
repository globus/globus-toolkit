#include "globus_gram_client.h"

int main(int argc, char *argv[])
{
    globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return 0;
}
