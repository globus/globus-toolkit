#include "globus_i_xio.h"

void
globus_xio_driver_pass_open_DEBUG(
    globus_result_t * _out_res,
    globus_xio_context_t * _out_context,
    globus_xio_operation_t  _in_op,
    globus_xio_driver_callback_t _in_cb,
    void * _in_user_arg) 
{                                                                           
    globus_i_xio_op_t *                             _op;                    
    globus_i_xio_handle_t *                         _handle;                
    globus_i_xio_context_t *                        _context;               
    globus_i_xio_context_entry_t *                  _my_context;            
    globus_i_xio_op_entry_t *                       _my_op;                 
    int                                             _caller_ndx;            
    globus_result_t                                 _res;                   
    globus_xio_driver_t                             _driver;                
    GlobusXIOName(GlobusXIODriverPassOpen);                                 
                                                                            
    globus_assert(_op->ndx < _op->stack_size);                              
    _op = (_in_op);                                                         
    _handle = _op->_op_handle;                                              
    _context = _handle->context;                                            
    _op->progress = GLOBUS_TRUE;                                            
    _op->block_timeout = GLOBUS_FALSE;                                      
                                                                            
    if(_op->canceled)                                                       
    {                                                                       
        _res = GlobusXIOErrorCanceled();                                    
    }                                                                       
    else                                                                    
    {                                                                       
        _my_context = &_context->entry[_op->ndx];                           
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPENING;               
        _caller_ndx = _op->ndx;                                             
                                                                            
        do                                                                  
        {                                                                   
            _my_op = &_op->entry[_op->ndx];                                 
            _driver = _context->entry[_op->ndx].driver;                     
            _op->ndx++;                                                     
        }                                                                   
        while(_driver->transport_open_func == NULL &&                       
              _driver->transform_open_func == NULL);                        
                                                                            
                                                                            
        _my_op->cb = (_in_cb);                                              
        _my_op->user_arg = (_in_user_arg);                                  
        _my_op->in_register = GLOBUS_TRUE;                                  
        _my_op->caller_ndx = _caller_ndx;                                   
        /* at time that stack is built this will be varified */             
        globus_assert(_op->ndx <= _context->stack_size);                    
        if(_op->ndx == _op->stack_size)                                     
        {                                                                   
            _res = _driver->transport_open_func(                            
                        _my_op->target,                                     
                        _my_op->attr,                                       
                        _my_context,                                        
                        _op);                                               
        }                                                                   
        else                                                                
        {                                                                   
            _res = _driver->transform_open_func(                            
                        _my_op->target,                                     
                        _my_op->attr,                                       
                        _op);                                               
        }                                                                   
        _my_op->in_register = GLOBUS_FALSE;                                 
        GlobusXIODebugSetOut(_out_context, _my_context);                    
        GlobusXIODebugSetOut(_out_res, _res);                               
    }                                                                       
}                                                                           


void
globus_xio_driver_finished_open_DEBUG(
    globus_xio_context_t                            _in_context,
    void *                                          _in_dh,
    globus_xio_operation_t                          _in_op,
    globus_result_t                                 _in_res)
{                                                                           
    globus_i_xio_op_t *                             _op;                    
    globus_i_xio_context_entry_t *                  _my_context;            
    globus_i_xio_context_t *                        _context;               
    globus_i_xio_op_entry_t *                       _my_op;                 
    globus_result_t                                 _res;                   
    int                                             _ctr;                   
                                                                            
    _res = (_in_res);                                                       
    _op = (globus_i_xio_op_t *)(_in_op);                                    
    globus_assert(_op->ndx >= 0);                                           
    _op->progress = GLOBUS_TRUE;                                            
    _op->block_timeout = GLOBUS_FALSE;                                      
                                                                            
    /*                                                                      
     * this means that we are finishing with a different context            
     * copy the finishing one into the operations;                          
     */                                                                     
    if(_op->_op_context != _in_context->whos_my_daddy &&                    
            _in_context != NULL)                                            
    {                                                                       
        globus_assert(0); /* for now we are dumping */                      
        /* iterate through them all and copy handles into new slot */       
        for(_ctr = _op->ndx + 1; _ctr < _op->stack_size; _ctr++)            
        {                                                                   
            _op->_op_context->entry[_ctr].driver_handle =                   
                _in_context->whos_my_daddy->entry[_ctr].driver_handle;      
        }                                                                   
    }                                                                       
                                                                            
    _context = _op->_op_context;                                            
    _my_op = &_op->entry[_op->ndx - 1];                                     
    _my_context = &_context->entry[_my_op->caller_ndx];                     
    _my_context->driver_handle = (_in_dh);                                  
    /* no operation can happen while in OPENING state so no need to lock */ 
    if(_res != GLOBUS_SUCCESS)                                              
    {                                                                       
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                
    }                                                                       
    else                                                                    
    {                                                                       
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_OPEN;                  
        globus_mutex_lock(&_context->mutex);                                
        {                                                                   
            _context->ref++;                                                
        }                                                                   
        globus_mutex_unlock(&_context->mutex);                              
    }                                                                       
                                                                            
    /* if still in register call stack or at top level and a user           
       requested a callback space */                                        
    if(_my_op->in_register ||                                               
        _my_context->space != GLOBUS_CALLBACK_GLOBAL_SPACE)                 
    {                                                                       
        _op->cached_res = _res;                                             
        globus_callback_space_register_oneshot(                             
            NULL,                                                           
            NULL,                                                           
            globus_l_xio_driver_op_kickout,                                 
            (void *)_op,                                                    
            _my_context->space);                                            
    }                                                                       
    else                                                                    
    {                                                                       
        _op->ndx = _my_op->caller_ndx;                                      
        _my_op->cb(_op, _res,                                               
            _my_op->user_arg);                                              
    }                                                                       
}                                                                           

void
globus_xio_driver_pass_close_DEBUG(
    globus_result_t *                               _out_res,
    globus_xio_operation_t                          _in_op,
    globus_xio_driver_callback_t                    _in_cb,
    void *                                          _in_ua) 
{                                                                           
    globus_i_xio_op_t *                             _op;                    
    globus_i_xio_handle_t *                         _handle;                
    globus_i_xio_context_t *                        _context;               
    globus_i_xio_context_entry_t *                  _my_context;            
    globus_bool_t                                   _pass;                  
    globus_i_xio_op_entry_t *                       _my_op;                 
    int                                             _caller_ndx;            
    globus_result_t                                 _res = GLOBUS_SUCCESS;  
    globus_xio_driver_t                             _driver;                
    GlobusXIOName(GlobusXIODriverPassClose);                                
                                                                            
    globus_assert(_op->ndx < _op->stack_size);                              
    _op = (_in_op);                                                         
    _handle = _op->_op_handle;                                              
    _context = _handle->context;                                            
    _op->progress = GLOBUS_TRUE;                                            
    _op->block_timeout = GLOBUS_FALSE;                                      
                                                                            
    if(_op->canceled)                                                       
    {                                                                       
        _res = GlobusXIOErrorCanceled();                                    
    }                                                                       
    else                                                                    
    {                                                                       
        _caller_ndx = _op->ndx;                                             
        _my_context = &_context->entry[_op->ndx];                           
                                                                            
        do                                                                  
        {                                                                   
            _my_op = &_op->entry[_op->ndx];                                 
            _driver = _context->entry[_op->ndx].driver;                     
            _op->ndx++;                                                     
        }                                                                   
        while(_driver->close_func == NULL);                                 
                                                                            
                                                                            
        /* deal with context state */                                       
        globus_mutex_lock(&_my_context->mutex);                             
        {                                                                   
            switch(_my_context->state)                                      
            {                                                               
                case GLOBUS_XIO_HANDLE_STATE_OPEN:                          
                    _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSING;   
                    break;                                                  
                                                                            
                case GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED:                  
                    _my_context->state =                                    
                        GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING;   
                    break;                                                  
                                                                            
                case GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED:                 
                    _my_context->state =                                    
                        GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING;  
                    break;                                                  
                                                                            
                default:                                                    
                    globus_assert(0);                                       
            }                                                               
            /* a barrier will never happen if the level above already did th
                close barrier and this level has not created any driver ops.
                in this case outstanding_operations is garentueed to be zero
            */                                                              
            if(_my_context->outstanding_operations == 0)                    
            {                                                               
                _pass = GLOBUS_TRUE;                                        
            }                                                               
            /* cache the op for close barrier */                            
            else                                                            
            {                                                               
                _pass = GLOBUS_FALSE;                                       
                _my_context->close_op = _op;                                
            }                                                               
        }                                                                   
        globus_mutex_unlock(&_my_context->mutex);                           
                                                                            
        _my_op->cb = (_in_cb);                                              
        _my_op->user_arg = (_in_ua);                                        
        _my_op->caller_ndx = _caller_ndx;                                   
        /* op can be checked outside of lock */                             
        if(_pass)                                                           
        {                                                                   
            _res = globus_i_xio_driver_start_close(_op, GLOBUS_TRUE);       
        }                                                                   
    }                                                                       
    if(_res != GLOBUS_SUCCESS)                                              
    {                                                                       
        _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                
    }                                                                       
    GlobusXIODebugSetOut(_out_res, _res);                                   
}                                                                           

void
globus_xio_driver_finished_close_DEBUG(
    globus_xio_operation_t                          op,
    globus_result_t                              _in_res)
{                                                                           
    globus_i_xio_op_t *                             _op;                    
    globus_i_xio_context_entry_t *                  _my_context;            
    globus_i_xio_context_t *                        _context;               
    globus_i_xio_op_entry_t *                       _my_op;                 
    globus_result_t                                 _res;                   
                                                                            
    _res = (_in_res);                                                       
    _op = (globus_i_xio_op_t *)(op);                                        
    globus_assert(_op->ndx > 0);                                            
    _op->progress = GLOBUS_TRUE;                                            
    _op->block_timeout = GLOBUS_FALSE;                                      
                                                                            
    _context = _op->_op_context;                                            
    _my_op = &_op->entry[_op->ndx - 1];                                     
    _my_context = &_context->entry[_my_op->caller_ndx];                     
                                                                            
    /* don't need to lock because barrier makes contntion not possible */   
    _my_context->state = GLOBUS_XIO_HANDLE_STATE_CLOSED;                    
                                                                            
    globus_assert(_op->ndx >= 0); /* otherwise we are not in bad memory */  
    /* space is only not global by user request in the top level of the     
     * of operations */                                                     
    _op->cached_res = (_in_res);                                            
    if(_my_op->in_register ||                                               
            _my_context->space != GLOBUS_CALLBACK_GLOBAL_SPACE)             
    {                                                                       
        globus_callback_space_register_oneshot(                             
            NULL,                                                           
            NULL,                                                           
            globus_l_xio_driver_op_kickout,                                 
            (void *)_op,                                                    
            _my_context->space);                                            
    }                                                                       
    else                                                                    
    {                                                                       
        _op->ndx = _my_op->caller_ndx;                                      
        _my_op->cb(_op, _op->cached_res, _my_op->user_arg);                 
    }                                                                       
}                                                                           
