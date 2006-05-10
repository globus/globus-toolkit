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

/********************************************************************
 *
 ********************************************************************/
#include "globus_common_include.h"
#include "globus_range_list.h"
#include "globus_libc.h"

typedef struct globus_l_range_ent_s
{
    globus_off_t                        offset;
    globus_off_t                        length;
    struct globus_l_range_ent_s *       next;
} globus_l_range_ent_t;

typedef struct globus_l_range_list_s
{
    int                                 size;
    globus_l_range_ent_t *              head;
} globus_l_range_list_t;

int
globus_range_list_init(
    globus_range_list_t *               range_list)
{
    globus_l_range_list_t *             rl;

    rl = (globus_l_range_list_t *) globus_calloc(
        sizeof(globus_l_range_list_t), 1);
    if(rl == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_MEMORY;
    }

    *range_list = rl;

    return GLOBUS_SUCCESS;
}

int
globus_range_list_merge_destructive(
    globus_range_list_t *               dest,
    globus_range_list_t                 src1,
    globus_range_list_t                 src2)
{
    globus_l_range_list_t *             tmp_dst;
    globus_l_range_ent_t *              ent1 = NULL;
    globus_l_range_ent_t *              ent2 = NULL;
    int                                 size_inc = 0;
    int                                 ent2_size = 0;
    int                                 rc;

    if(src1 == NULL || src2 == NULL)
    {
        return -1;
    }
    rc = globus_range_list_init(&tmp_dst);
    if(rc != 0)
    {
        return -1;
    }
    
    if(src1->head == NULL)
    {
        tmp_dst->head = src2->head;
        tmp_dst->size = src2->size;
    }
    else if(src2->head == NULL)
    {
        tmp_dst->head = src1->head;
        tmp_dst->size = src1->size;
    }
    else if(src1->head->offset <= src2->head->offset)
    {
        tmp_dst->head = src1->head;
        tmp_dst->size = src1->size;
        ent1 = src1->head;
        ent2 = src2->head;
        ent2_size = src2->size;
    }
    else
    {
        tmp_dst->head = src2->head;
        tmp_dst->size = src2->size;
        ent1 = src2->head;
        ent2 = src1->head;
        ent2_size = src1->size;
    }

    /* we're going to move or free every entry... null out the source lists
    so the user can destroy or reuse them safely */
    src1->head = NULL;
    src2->head = NULL;
    src1->size = 0;
    src2->size = 0;

    if(ent1 && ent2)
    {
        globus_l_range_ent_t *              curr1;
        globus_l_range_ent_t *              curr2;
        globus_l_range_ent_t *              prev;
        globus_l_range_ent_t *              next;
        globus_off_t                        curr1_end;
        globus_off_t                        curr2_end;
        globus_bool_t                       done = GLOBUS_FALSE;

        while(ent2)
        {
            curr2 = ent2;
            if(curr2->length == GLOBUS_RANGE_LIST_MAX)
            {
                curr2_end = GLOBUS_RANGE_LIST_MAX;
            }
            else
            {
                curr2_end = curr2->offset + curr2->length;
            }
            prev = NULL;
            while(ent1 != NULL && !done)
            {
                curr1 = ent1;
                if(curr1->length == GLOBUS_RANGE_LIST_MAX)
                {
                    curr1_end = GLOBUS_RANGE_LIST_MAX;
                }
                else
                {
                    curr1_end = curr1->offset + curr1->length;
                }
                next = curr1->next;
                /* if it is discontigous and in front of this one - this if
                   will not be entered on the first iteration */
                if(curr2_end < curr1->offset &&
                    curr2_end != GLOBUS_RANGE_LIST_MAX)
                {
                    prev->next = curr2;
                    ent2 = curr2->next;
                    curr2->next = curr1;
                    ent1 = curr2;
                    done = GLOBUS_TRUE;
                    size_inc++;
                }
                /* if it is merging */
                else if((curr2_end >= curr1->offset ||
                    curr2_end == GLOBUS_RANGE_LIST_MAX)
                    && (curr2->offset <= curr1_end ||
                    curr1_end == GLOBUS_RANGE_LIST_MAX))
                {
                    if(curr2->offset < curr1->offset)
                    {
                        curr1->offset = curr2->offset;
                    }
                    if(curr2_end == GLOBUS_RANGE_LIST_MAX ||
                        curr1_end == GLOBUS_RANGE_LIST_MAX)
                    {
                        curr1->length = GLOBUS_RANGE_LIST_MAX;
                    }
                    else if(curr2_end > curr1_end)
                    {
                        curr1->length = curr2_end - curr1->offset;
                    }
                    if(next != NULL && curr2_end >= next->offset)
                    {
                        if(next->length == GLOBUS_RANGE_LIST_MAX)
                        {
                            curr1->length = GLOBUS_RANGE_LIST_MAX;
                        } 
                        else
                        {
                            curr1->length =
                                next->offset + next->length - curr1->offset;
                        }
                        size_inc--;
                        curr1->next = next->next;
                        globus_free(next);
                    } 
                    ent2 = curr2->next;
                    globus_free(curr2);
                    ent1 = curr1;
                    done = GLOBUS_TRUE;
                }
                else
                {   
                    prev = curr1;
                    ent1 = curr1->next;
                }
            }      
            /* must be last entry - if we hit this, we can just point
               prev->next to curr2 (ent2) and thats it */
            if(!done)
            {       
                prev->next = curr2;
                ent2 = NULL;
                size_inc += ent2_size;
            }       
            else    
            {   
                ent2_size--;
                done = GLOBUS_FALSE;
            }   
        }           
        tmp_dst->size += size_inc;
    }
    
    *dest = tmp_dst;               
    return GLOBUS_SUCCESS;
}                   

int
globus_range_list_copy(
    globus_range_list_t *               dest,
    globus_range_list_t                 src)
{
    int                                 rc;
    globus_l_range_list_t *             tmp_dst;
    globus_l_range_ent_t *              prev = NULL;
    globus_l_range_ent_t *              dst_ent;
    globus_l_range_ent_t *              src_ent;

    if(src == NULL)
    {
        return -1;
    }
    
    rc = globus_range_list_init(&tmp_dst);
    if(rc != 0)
    {
        return -1;
    }

    src_ent = src->head;        
    while(src_ent != NULL)
    {
        dst_ent = (globus_l_range_ent_t *) 
            globus_malloc(sizeof(globus_l_range_ent_t));
        if(dst_ent == NULL)
        {
            goto err;
        }
        dst_ent->offset = src_ent->offset;
        dst_ent->length = src_ent->length;
        dst_ent->next = NULL;
        
        if(tmp_dst->head != NULL)
        {
            prev->next = dst_ent;
        }
        else
        {
            tmp_dst->head = dst_ent;
        }
        
        prev = dst_ent;
        src_ent = src_ent->next;
    }
    tmp_dst->size = src->size;
    
    *dest = tmp_dst;    
    return GLOBUS_SUCCESS;

err:
    globus_range_list_destroy(tmp_dst);
    return -1;
}

int
globus_range_list_merge(
    globus_range_list_t *               dest,
    globus_range_list_t                 src1,
    globus_range_list_t                 src2)
{
    int                                 rc;
    globus_range_list_t                 src1_tmp;
    globus_range_list_t                 src2_tmp;

    if(src1 == NULL && src2 == NULL)
    {
        return -1;
    }
    
    rc = globus_range_list_copy(&src1_tmp, src1);
    if(rc != 0)
    {
        return -1;
    }
    
    rc = globus_range_list_copy(&src2_tmp, src2);
    if(rc != 0)
    {
        goto err1;
    }
    
    rc = globus_range_list_merge_destructive(dest, src1_tmp, src2_tmp);
    if(rc != 0)
    {
        goto err2;
    }
    
    globus_range_list_destroy(src2_tmp);   
    globus_range_list_destroy(src1_tmp);
    
    return GLOBUS_SUCCESS;

err2:
    globus_range_list_destroy(src2_tmp);   
err1:
    globus_range_list_destroy(src1_tmp);   
    return -1;
}


void
globus_range_list_destroy(
    globus_range_list_t                 range_list)
{
    globus_l_range_ent_t *              i;
    globus_l_range_ent_t *              j;

    if(range_list == NULL)
    {
        return;
    }

    i = range_list->head;
    while(i != NULL)
    {
        j = i;
        i = i->next;
        globus_free(j);
    }
    globus_free(range_list);
}

int
globus_range_list_insert(
    globus_range_list_t                 range_list,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    globus_l_range_ent_t *              prev;
    globus_l_range_ent_t *              ent;
    globus_l_range_ent_t *              next;
    globus_l_range_ent_t *              new_ent;
    globus_off_t                        end_offset;
    globus_off_t                        ent_end;
    globus_bool_t                       done = GLOBUS_FALSE;

    if(offset < 0)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }
    if(length == 0)
    {
        return GLOBUS_SUCCESS;
    }
    
    if(range_list->head == NULL)
    {
        new_ent = (globus_l_range_ent_t *) globus_malloc(
            sizeof(globus_l_range_ent_t));
        if(new_ent == NULL)
        {
            globus_assert(0);
        }
        new_ent->offset = offset;
        new_ent->length = length;
        new_ent->next = NULL;
        range_list->head = new_ent;
        range_list->size = 1;
        
        return GLOBUS_SUCCESS;
    }

    if(length == GLOBUS_RANGE_LIST_MAX)
    {
        end_offset = GLOBUS_RANGE_LIST_MAX;
    }
    else
    {
        end_offset = offset + length;
    }

    prev = NULL;
    ent = range_list->head;
    while(ent != NULL && !done)
    {
        if(ent->length == GLOBUS_RANGE_LIST_MAX)
        {
            ent_end = GLOBUS_RANGE_LIST_MAX;
        }
        else
        {
            ent_end = ent->offset + ent->length;
        }
        next = ent->next;
        /* if it is discontigous and in front of this one */
        if(end_offset < ent->offset && end_offset != GLOBUS_RANGE_LIST_MAX)
        {
            new_ent = (globus_l_range_ent_t *) globus_malloc(
                sizeof(globus_l_range_ent_t));
            if(new_ent == NULL)
            {
                globus_assert(0);
            }
            new_ent->offset = offset;
            new_ent->length = length;
            new_ent->next = ent;
            if(prev == NULL)
            {
                range_list->head = new_ent;
            }
            else
            {
                prev->next = new_ent;
            }
            range_list->size++;
            done = GLOBUS_TRUE;
        }
        /* if it is merging */
        else if((end_offset >= ent->offset || 
            end_offset == GLOBUS_RANGE_LIST_MAX) 
            && (offset <= ent_end || 
            ent_end == GLOBUS_RANGE_LIST_MAX))
        {
            if(offset < ent->offset)
            {
                ent->offset = offset;
            }
            if(end_offset == GLOBUS_RANGE_LIST_MAX || 
                ent_end == GLOBUS_RANGE_LIST_MAX)
            {
                ent->length = GLOBUS_RANGE_LIST_MAX;
            }
            else if(end_offset > ent_end)
            {
                ent->length = end_offset - ent->offset;
            }
            if(next != NULL && end_offset >= next->offset)
            {
                if(next->length == GLOBUS_RANGE_LIST_MAX)
                {
                    ent->length = GLOBUS_RANGE_LIST_MAX;    
                }
                else
                {   
                    ent->length = next->offset + next->length - ent->offset;
                }
                range_list->size--;
                ent->next = next->next;
                globus_free(next);
            }
            done = GLOBUS_TRUE;
        }
        else
        {
            prev = ent;
            ent = ent->next;
        }
    }
    /* must be last entry */
    if(!done)
    {
        new_ent = (globus_l_range_ent_t *) globus_malloc(
            sizeof(globus_l_range_ent_t));
        if(new_ent == NULL)
        {
            globus_assert(0);
        }
        new_ent->offset = offset;
        new_ent->length = length;
        new_ent->next = ent;

        globus_assert(prev != NULL);
        prev->next = new_ent;
        range_list->size++;
    }

    return GLOBUS_SUCCESS;
}

int
globus_range_list_remove(
    globus_range_list_t                 range_list,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    globus_l_range_ent_t *              prev;
    globus_l_range_ent_t *              ent;
    globus_l_range_ent_t *              next;
    globus_l_range_ent_t *              new_ent;
    globus_off_t                        end_offset;
    globus_off_t                        ent_end;
    globus_bool_t                       done = GLOBUS_FALSE;

    if(offset < 0)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }
    if(length == 0)
    {
        return GLOBUS_SUCCESS;
    }

    if(length == GLOBUS_RANGE_LIST_MAX)
    {
        end_offset = GLOBUS_RANGE_LIST_MAX;
    }
    else
    {
        end_offset = offset + length;
    }
    prev = NULL;
    ent = range_list->head;
    while(ent != NULL && !done)
    {
        next = ent->next;
        if(ent->length == GLOBUS_RANGE_LIST_MAX)
        {
            ent_end = GLOBUS_RANGE_LIST_MAX;
        }
        else
        {
            ent_end = ent->offset + ent->length;
        }
        
        /* this range is all foul, remove it */
        if(ent->offset >= offset && 
            ((ent_end <= end_offset && ent_end != GLOBUS_RANGE_LIST_MAX) || 
            end_offset == GLOBUS_RANGE_LIST_MAX))
        {
            if(prev == NULL)
            {
                range_list->head = next;
            }
            else
            {
                prev->next = next;
            }
            range_list->size--;
            globus_free(ent);
        }
        /* this range starts fair and extends foul, adjust length */
        else if(ent->offset < offset && 
            ((ent_end < end_offset && ent_end != GLOBUS_RANGE_LIST_MAX) ||
                end_offset == GLOBUS_RANGE_LIST_MAX) && 
            (ent_end > offset || ent_end == GLOBUS_RANGE_LIST_MAX))
        {   
            ent->length = offset - ent->offset;
            prev = ent;
        }
        /* this range starts foul and extends fair, adjust offset */
        else if(ent->offset >= offset && ent->offset < end_offset &&
            ((ent_end > end_offset && end_offset != GLOBUS_RANGE_LIST_MAX) || 
                ent_end == GLOBUS_RANGE_LIST_MAX))
        {
            ent->offset = end_offset;
            prev = ent;
            done = GLOBUS_TRUE;
        }
        /* this range starts fair and ends fair, but crosses foul,
             adjust offset and length */
        else if(ent->offset < offset && 
            ((ent_end > end_offset && end_offset != GLOBUS_RANGE_LIST_MAX) || 
            ent_end == GLOBUS_RANGE_LIST_MAX))
        {
            new_ent = (globus_l_range_ent_t *) globus_malloc(
                sizeof(globus_l_range_ent_t));
            if(new_ent == NULL)
            {
                globus_assert(0);
            }
            new_ent->next = NULL;
            new_ent->offset = end_offset;
            if(ent_end == GLOBUS_RANGE_LIST_MAX)
            {
                new_ent->length = GLOBUS_RANGE_LIST_MAX;    
            }
            else
            {   
                new_ent->length = ent_end - new_ent->offset;
            }
            ent->length = offset - ent->offset;
            ent->next = new_ent;
    
            range_list->size++;
            
            prev = ent;
            done = GLOBUS_TRUE;
        }
        /* this range is all fair */
        else
        {
            if(ent->offset > end_offset && end_offset != GLOBUS_RANGE_LIST_MAX)
            {
                done = GLOBUS_TRUE;
            }
            prev = ent;
        }
        ent = next;
    }

    return GLOBUS_SUCCESS;
}

int
globus_range_list_size(
    globus_range_list_t                 range_list)
{
    if(range_list == NULL)
    {
        return 0;
    }

    return range_list->size;
}

int
globus_range_list_at(
    globus_range_list_t                 range_list,
    int                                 ndx,
    globus_off_t *                      offset,
    globus_off_t *                      length)
{
    int                                 ctr;
    globus_l_range_ent_t *              i;

    if(range_list == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }
    if(offset == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }
    if(length == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }

    i = range_list->head;
    for(ctr = 0; ctr < ndx; ctr++)
    {
        if(i == NULL)
        {
            return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
        }
        i = i->next;
    }

    *offset = i->offset;
    *length = i->length;

    return GLOBUS_SUCCESS;
}

int
globus_range_list_remove_at(
    globus_range_list_t                 range_list,
    int                                 ndx,
    globus_off_t *                      offset,
    globus_off_t *                      length)
{
    int                                 ctr;
    globus_l_range_ent_t *              i;
    globus_l_range_ent_t *              prev;

    if(range_list == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }
    if(offset == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }
    if(length == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }

    prev = NULL;
    i = range_list->head;
    for(ctr = 0; ctr < ndx; ctr++)
    {
        if(i == NULL)
        {
            return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
        }
        prev = i;
        i = i->next;
    }

    if(i == NULL)
    {
        return GLOBUS_RANGE_LIST_ERROR_PARAMETER;
    }

    if(prev == NULL)
    {
        range_list->head = i->next;
    }
    else
    {
        prev->next = i->next;
    }

    range_list->size--;
    
    *offset = i->offset;
    *length = i->length;
    globus_free(i);

    return GLOBUS_SUCCESS;
}
