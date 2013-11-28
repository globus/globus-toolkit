static int failed = 0;
static void ok(int predval, const char *name)
{
    printf("%s # %s\n", predval ? "ok" : "not ok", name);
    if (!predval)
    {
        failed++;
    }
}
