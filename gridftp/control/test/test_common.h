/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#if !defined(TEST_COMMON_H)
#define      TEST_COMMON_H 1

extern int                                    verbose_print_level;

typedef struct ftp_test_monitor_s 
{
    globus_mutex_t                            mutex;
    globus_cond_t                             cond;
    globus_bool_t                             done;
    int                                       count;
    globus_result_t                           result;
    void *                                    user_arg;
} ftp_test_monitor_t;

typedef struct globus_ftp_control_fake_file_t
{
    globus_byte_t *                           buffer;
    int                                       chunk_size;
    int                                       file_size;
    int                                       offset;
} globus_ftp_control_fake_file_t;

void
ftp_test_monitor_init(
    ftp_test_monitor_t *                     monitor);

void
ftp_test_monitor_reset(
    ftp_test_monitor_t *                     monitor);

void
ftp_test_monitor_done_wait(
    ftp_test_monitor_t *                     monitor);

void
ftp_test_monitor_count_wait(
    ftp_test_monitor_t *                     monitor,
    int                                      count);

void
ftp_test_monitor_signal(
    ftp_test_monitor_t *                     monitor);

void
help_print();

void
fake_file_init(
    globus_ftp_control_fake_file_t *          fake_file,
    int                                       file_size,
    int                                       chunk_size);

void 
fake_file_destroy(
    globus_ftp_control_fake_file_t *          fake_file);

globus_byte_t *
fake_file_get_chunk(
    globus_ftp_control_fake_file_t *          fake_file,
    int *                                     size);

globus_bool_t
fake_file_is_eof(
    globus_ftp_control_fake_file_t *          fake_file);

globus_bool_t
fake_file_seek(
    globus_ftp_control_fake_file_t *          fake_file,
    int                                       offset);

globus_bool_t
fake_file_cmp(
    globus_ftp_control_fake_file_t *          fake_file,
    globus_byte_t *                           buffer,
    int                                       offset,
    int                                       length);

void 
verbose_printf(
    int                                       level, 
    char *                                    s, 
    ...);

globus_bool_t
pasv_to_host_port(
    char *                                      astr,
    globus_ftp_control_host_port_t *            addr);

globus_bool_t
disconnect_control_handle(
    globus_ftp_control_handle_t *               control_handle);
globus_bool_t
connect_control_handle(
    globus_ftp_control_handle_t *               control_handle,
    char *                                      user_name,
    char *                                      password,
    char *                                      base_dir,
    char *                                      hostname,
    unsigned short                              port);

void
ftp_test_monitor_destroy(
    ftp_test_monitor_t *                     monitor);

#endif
