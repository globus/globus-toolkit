/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_ftp_control_test.h"


void
callback_func(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

int 
data_commands_before_connect_menu();


globus_bool_t
data_commands_connect_test(
    globus_ftp_control_handle_t *               handle)
{
    globus_result_t                             result;
    int                                         choice ;
    globus_byte_t                               *buff;
    globus_size_t                               maxlength ;
    unsigned int				channels;
    

    printf(" Testing Globus Data Commands before Connect \n");
    choice = data_commands_before_connect_menu();
    switch(choice){

    case 1: 
            result = globus_ftp_control_data_connect_read(
                         handle,
                         GLOBUS_NULL,
                         GLOBUS_NULL);
	    if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_connect_read before calling connect \n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 2: 
            result = globus_ftp_control_data_connect_write(
                         handle,
                         GLOBUS_NULL,
                         GLOBUS_NULL);
	    if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_connect_write before calling connect\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 3:
            result =  globus_ftp_control_data_add_channels(handle,1,1);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_add_chennels before calling connect\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 4:
            result =  globus_ftp_control_data_query_channels(handle,&channels,1);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_query_channels before calling connect\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 5:
            result =  globus_ftp_control_data_read(
		handle,
		buff,
		maxlength,
		(globus_ftp_control_data_callback_t) callback_func,
		GLOBUS_NULL);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_read before calling connect\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 6:
            result =  globus_ftp_control_data_remove_channels(handle,1,1);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_remove_channel before calling connect\n");
		return GLOBUS_FALSE ;
	      }
	    break;


	    
    default: printf("data commands before connect test over\n");
    }
    return GLOBUS_SUCCESS ;
   
}

globus_bool_t
data_commands_pasvorport_test(
    globus_ftp_control_handle_t *               handle)
{
    globus_result_t                             result;
    int                                         choice ;
    globus_byte_t                               *buff;
    globus_size_t                               maxlength ;
    unsigned int				channels;

    printf(" Testing Globus Data Commands before Calling Pasv/Port  \n");
    choice = data_commands_before_connect_menu();
    switch(choice){

    case 1: 
            result = globus_ftp_control_data_connect_read(
                         handle,
                         GLOBUS_NULL,
                         GLOBUS_NULL);
	    if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_connect_read before calling Pasv/Port \n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 2: 
            result = globus_ftp_control_data_connect_write(
                         handle,
                         GLOBUS_NULL,
                         GLOBUS_NULL);
	    if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_connect_write before calling Pasv/Port\n");
		return GLOBUS_FALSE ;
	      }
	    break;
    case 3:
           result =  globus_ftp_control_data_add_channels(handle,1,1);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_add_chennels before calling Pasv/Port\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 4:
            result =  globus_ftp_control_data_query_channels(handle,&channels,1);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_query_channels before calling Pasv/Port\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 5:
            result =  globus_ftp_control_data_read(
		handle,
		buff,
		maxlength,
		(globus_ftp_control_data_callback_t)callback_func,
		GLOBUS_NULL);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_read before calling Pasv/Port\n");
		return GLOBUS_FALSE ;
	      }
	    break;

    case 6:
            result =  globus_ftp_control_data_remove_channels(handle,1,1);
            if ( result != GLOBUS_SUCCESS)
	      {
		printf("Failure: data_remove_channel before calling Pasv/Port\n");
		return GLOBUS_FALSE ;
	      }
	    break;
	    
    default: printf("data commands before calling Pasv/Port test over\n");

    }
    return GLOBUS_SUCCESS ;
   
}


int data_commands_before_connect_menu()
{
  int option ;

  printf("enter 1 for globus_ftp_control_data_connect_read()\n");
  printf("enter 2 for globus_ftp_control_data_connect_write()\n");
  printf("enter 3 for globus_ftp_control_data_add_channel()\n");
  printf("enter 4 for globus_ftp_control_data_query_channels()\n");
  printf("enter 5 for globus_ftp_control_data_read()\n");
  printf("enter 6 for globus_ftp_control_data_remove_channels()\n");
  
  printf("enter ur option \n");
  scanf("%d",&option);

  return option;
}
	
void
callback_func(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
  return;
}





