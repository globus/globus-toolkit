#if !defined (GLOBUS_L_XIO_DRIVER_H)
#define GLOBUS_L_XIO_DRIVER_H 1

#define GlobusXIODriverAttrInit(__res, __driver, __out_ptr)             \
{                                                                       \
    __res = __driver->attr_init_func(&__out_ptr);                       \
}

#define GlobusXIODriverAttrCntl(__res, __driver, __dsa, __cmd, __ap)    \
{                                                                       \
    __res = __driver->attr_cntl_func(__dsa, __cmd, __ap);               \
}

#define GlobusXIODriverAttrDestroy(__res, __driver, __dsa)              \
{                                                                       \
    __res = __driver->attr_destroy_func(__dsa);                         \
}

#define GlobusXIODriverAttrCopy(__res, __driver, __dst, __src)          \
{                                                                       \
    __res = __driver->attr_copy_func(__dst, __src);                     \
}

#endif
