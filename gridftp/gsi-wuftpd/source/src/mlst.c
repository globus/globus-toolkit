void 
mlst(const char *file, const char *facts)
{
    char *ret_val = (char *)malloc(512);    
    char *full_path = (char *) malloc(strlen(file));
    char *fact_str = (char *) malloc(512);
    char *vpath = (char *)malloc(512);
    
    memcpy(ret_val, "\0", 512);
    memcpy(vpath, "\0", 512);
    memcpy(full_path, "\0", 512);
    memcpy(fact_str, "\0", 512);
    mapping_getcwd(vpath, 512);

    if(*file == '/') 
    {
        sprintf(full_path, "%s", file);
    }
    else
    {
        sprintf(full_path, "%s/%s", vpath, file);
    }
    
    if(get_fact_list(fact_str, 512, full_path, facts)) 
    {
        reply(501, "No such file or insufficient permissions");
    }
    else 
    {
        lreply(250, "Listing %s", full_path);
        lreply(0, " %s %s", fact_str, full_path);
        reply(250, "End of status");
    }
    

    return;
    
}
