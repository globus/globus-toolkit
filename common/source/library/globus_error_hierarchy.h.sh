#! /bin/sh

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 



generate_type_def ()
{
   case $1 in
     declarations)
        echo "extern const globus_object_type_t"
        echo "             GLOBUS_ERROR_TYPE_${type}_DEFINITION;"
        echo ""
        echo "#define GLOBUS_ERROR_TYPE_${type} \\"
        echo "        (&GLOBUS_ERROR_TYPE_${type}_DEFINITION)"
        echo ""
     ;;
     definitions)
        echo "const globus_object_type_t GLOBUS_ERROR_TYPE_${type}_DEFINITION"
        echo "= globus_error_type_static_initializer ("
        echo "        (&GLOBUS_ERROR_TYPE_${ptype}_DEFINITION),"

        if [ ! "X$fields" = "X" ]
        then
           echo "        globus_l_error_${typelc}_copy,"
           echo "        globus_l_error_${typelc}_destroy,"
        else
           echo "        NULL,"
           echo "        NULL,"
        fi

        echo "        (${stringfunc}));"
        echo ""
     ;;
     *)
        :
     ;;
   esac
}

generate_type_constructor_args ()
{
   fieldcount=0
   IFS=,

   case $1 in
      references | declarations | docmethods)
         eval "myfields=\"\${afields_${type}}"\"
      ;;
      preferences)
         eval "myfields=\"\${afields_${ptype}}"\"
      ;;
      copyins)
         eval "myfields=\"$fields\""
      ;;
   esac

   for field in $myfields
   do
      fieldtype="`echo $field | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
      fieldname="`echo $field | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
      if [ "X$fieldtype" = "X" ]
      then
         fieldtype="globus_object_t *"
      fi

      case $1 in 
         copyins | docmethods)
           :
         ;;
         references | preferences | declarations)
            if expr $fieldcount \> 0 2>&1 > /dev/null
            then
               echo ","
            fi
         ;;
      esac

      case $1 in 
         declarations)
            echo -n "    ${fieldtype} ${fieldname}"
         ;;
         docmethods)
            echo "   <farg> <fargtype> ${fieldtype} </fargtype>"
            echo "          <fargname> ${fieldname} </fargname> </farg>"
         ;;
         references | preferences)
            echo -n "    ${fieldname}"
         ;;
         copyins)
            echo "  globus_error_${typelc}_set_${fieldname} (error, ${fieldname});"
         ;;
      esac

      fieldcount=`expr $fieldcount + 1`
   done
   IFS=":{}"
}

generate_type_constructors ()
{
   case $1 in
      declarations | definitions)
         echo    "/* allocate and initialize an error of type"
         echo    " * GLOBUS_ERROR_TYPE_${type}   */"
         echo    "extern globus_object_t *"
         echo    "globus_error_construct_${typelc} ("

         generate_type_constructor_args declarations

   echo -n ")"
      ;;
      docmethods)
         cat <<EOF
<func>
<type> globus_object_t * </type>
<name> globus_error_construct_${typelc} </name>
<fargs>
EOF
         generate_type_constructor_args docmethods
         
         cat <<EOF
</fargs>
<description>

Equivalent to:<br>
<tab>  globus_error_initialize_${typelc} (<br>
<tab> <tab> <tab> <tab> globus_object_construct( <ref> GLOBUS_ERROR_TYPE_${type} </ref> ) . . . ) .

</description>
</func>

EOF
      ;;
   esac
   case $1 in 
      declarations)
        echo ";"
      ;;
      definitions)
        echo ""
        echo "{"
        echo "  globus_object_t * newerror, * error;"
        echo "  newerror = globus_object_construct (GLOBUS_ERROR_TYPE_${type});"
        echo ""
        echo "  error = globus_error_initialize_${typelc} ("

   eval "ifields=\"\${afields_${type}}\""

   if [ ! "X$ifields" = "X" ]
   then
        echo    "    newerror,"
   else
        echo    "    newerror"
   fi

        generate_type_constructor_args references
        echo ");"
        echo ""
        echo "  if (error==NULL) globus_object_free (newerror);"
        echo ""
        echo "  return error;"
        echo "}"
      ;;
   esac

   echo    ""

   case $1 in
      declarations | definitions)
   echo    "/* initialize and return an error of type"
   echo    " * GLOBUS_ERROR_TYPE_${type}   */"
   echo    "extern globus_object_t *"
   echo    "globus_error_initialize_${typelc} ("

   eval "ifields=\"\${afields_${type}}\""

   if [ ! "X$ifields" = "X" ]
   then
        echo    "    globus_object_t * error,"
   else
        echo    "    globus_object_t * error"
   fi

   generate_type_constructor_args declarations

   echo -n ")"
      ;;
      docmethods)
         cat <<EOF
<func>
<type> globus_object_t * </type>
<name> globus_error_initialize_${typelc} </name>
<fargs>
    <farg> <fargtype> globus_object_t * </fargtype>
           <fargname> error </fargname> </farg>
EOF
         generate_type_constructor_args docmethods
         
         cat <<EOF
</fargs>
<description>

Initialize the instance data of error with the given values and return 
the error, or return NULL if either error is NULL,
error is static, or error is not derived from 
<ref> GLOBUS_ERROR_TYPE_${type} </ref> . 

</description>
</func>

EOF
      ;;
   esac
   case $1 in 
      declarations)
         echo ";"
      ;;
      definitions)
        echo ""
        echo "{"
        generate_type_constructor_args copyins
        echo ""
        echo "  return globus_error_initialize_${ptypelc} ("

   eval "ifields=\"\${afields_${ptype}}\""

   if [ ! "X$ifields" = "X" ]
   then
        echo    "    error,"
   else
        echo    "    error"
   fi
        generate_type_constructor_args preferences
        echo ");"
        echo "}"
      ;;
   esac

   echo    ""
}

generate_type_instance_type ()
{
   if [ "$1" = "definitions" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "typedef struct globus_error_${typelc}_instance_s {"

      IFS=,
      for field in $fields
      do
         fieldtype="`echo $field \
                       | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
         fieldname="`echo $field \
                       | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
         if [ "X$fieldtype" = "X" ]
         then
            fieldtype="globus_object_t *"
         fi

         echo "  ${fieldtype}   ${fieldname};"
      done
      IFS=":{}"

      echo "} globus_error_${typelc}_instance_t;"
      echo ""

      echo "static globus_error_${typelc}_instance_t *"
      echo "globus_l_error_${typelc}_instance_data (globus_object_t *error)"
      echo "{"
      echo "  globus_error_${typelc}_instance_t * instance_data;"
      echo "  globus_object_t * local_object;"
      echo ""
      echo "  local_object "
      echo "  = globus_object_upcast (error, GLOBUS_ERROR_TYPE_${type});"
      echo ""
      echo "  if (local_object==NULL) return NULL;"
      echo ""
      echo "  instance_data "
      echo "  = ((globus_error_${typelc}_instance_t *)"
      echo "     globus_object_get_local_instance_data (local_object));"
      echo ""
      echo "  if (instance_data!=NULL) return instance_data;"
      echo "  else {"
      echo "    instance_data "
      echo "    = globus_malloc (sizeof(globus_error_${typelc}_instance_t));"
      echo "    globus_object_set_local_instance_data (local_object,"
      echo "                                           instance_data);"
      echo ""

      IFS=,
      for field in $fields
      do
         fieldtype="`echo $field \
                       | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
         fieldname="`echo $field \
                       | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
         if [ "X$fieldtype" = "X" ]
         then
            fieldtype="globus_object_t *"
         fi

         case "$fieldtype" in 
            *\*)
              echo "    instance_data->${fieldname} = NULL;"
            ;;
            int | long)
              echo "    instance_data->${fieldname} = -1;"
            ;;
            *)
              echo "warning: ${type}:${fieldname} is uninitialized!" 1>&2
              echo "    /* FIXME: ${fieldname} is uninitialized!! */"
            ;;
         esac
      done
      IFS=":{}"

      echo "    return instance_data;"
      echo "  }"
      echo "}"
      echo ""
   fi
}

generate_type_method_index ()
{
   cat <<EOF

<object> <type> globus_object_type_t * </type>
         <name> GLOBUS_ERROR_TYPE_${type} </name>
<description>

This type indicates that ${indication}.

<p>

This type introduces the following methods:
<ul>
   <li> <ref> globus_error_construct_${typelc} </ref> ()</li>
   <li> <ref> globus_error_initialize_${typelc} </ref> ()</li>
EOF

      IFS=,
      for field in $fields
      do
         fieldname="`echo $field \
                       | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
         cat <<EOF
   <li> <ref> globus_error_${typelc}_get_${fieldname} </ref> () /
        <ref> globus_error_${typelc}_set_${fieldname} </ref> ()</li>
EOF
     done
      IFS=":{}"

   cat <<EOF
</ul>

<p>

This type is derived from <ref> GLOBUS_ERROR_TYPE_${ptype} </ref> .

</description>
</object>

EOF
}

generate_type_instance_copy ()
{
   if [ "$1" = "definitions" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "static void globus_l_error_${typelc}_copy (void *srcvp, void **dstvpp)"
      echo "{"
      echo "  globus_error_${typelc}_instance_t *src, *dst;"
      echo "  if (srcvp==NULL || dstvpp==NULL) return;"
      echo "  src = ((globus_error_${typelc}_instance_t *) srcvp);"
      echo "  (*dstvpp) = globus_malloc (sizeof(globus_error_${typelc}_instance_t));"
      echo "  dst = ((globus_error_${typelc}_instance_t *) (*dstvpp));"
      echo "  if (dst==NULL) return;"

      IFS=,
      for field in $fields
      do
         fieldtype="`echo $field \
                       | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
         fieldname="`echo $field \
                       | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
         if [ "X$fieldtype" = "X" ]
         then
            fieldtype="globus_object_t *"
         fi

         if [ "X$fieldtype" = "Xglobus_object_t *" ]
         then
            echo "  dst->${fieldname} = globus_object_copy(src->${fieldname});"
         else
            echo "  dst->${fieldname} = src->${fieldname};"
         fi

      done
      IFS=":{}"

      echo "}"
      echo ""
   elif [ "$1" = "declarations" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "static void globus_l_error_${typelc}_copy (void *src, void **dst);"
      echo ""
   fi
}

generate_type_instance_destroy ()
{
   if [ "$1" = "definitions" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "static void globus_l_error_${typelc}_destroy (void *datavp)"
      echo "{"
      echo "  globus_error_${typelc}_instance_t *data;"
      echo "  if (datavp==NULL) return;"
      echo "  data = ((globus_error_${typelc}_instance_t *) datavp);"

      IFS=,
      for field in $fields
      do
         fieldtype="`echo $field \
                       | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
         fieldname="`echo $field \
                       | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
         if [ "X$fieldtype" = "X" ]
         then
            fieldtype="globus_object_t *"
         fi

         if [ "X$fieldtype" = "Xglobus_object_t *" ]
         then
            echo "  globus_object_free (data->${fieldname});"
            echo "  data->${fieldname} = NULL;"
         else
            :
         fi

      done
      IFS=":{}"

      echo "  globus_free (data);"
      echo "}"
      echo ""
   elif [ "$1" = "declarations" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "static void globus_l_error_${typelc}_destroy (void *data);"
      echo ""
   fi
}

generate_type_instance_accessors ()
{
   IFS=,
   for field in $fields
   do
      fieldtype="`echo $field | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
      fieldname="`echo $field | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
      if [ "X$fieldtype" = "X" ]
      then
         fieldtype="globus_object_t *"
      fi

      case "$fieldtype" in
         *\*)
           failval=NULL
         ;;
         int | long)
           failval=-1
         ;;
         *)
           failval=NULL
           echo "warning: ${type}::${fieldname} type getting unsupported treatment!" 1>&2
         ;;
      esac

      case $1 in
         docmethods)
            cat <<EOF

<func>
<type> ${fieldtype} </type>
<name> globus_error_${typelc}_get_${fieldname} </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
          <fargname> error </fargname> </farg> 
</fargs>
<description>

Returns the ${fieldname} with which the error is associated, 
or returns ${failval} if no ${fieldname} is known, if error is a static error, 
if error is not derived from <ref> GLOBUS_ERROR_TYPE_${type} </ref> ,
or if error is NULL.

<p>

</description>
</func>

EOF
         ;;
         definitions | declarations)

      echo    "/* return the ${fieldname} instance data of an error"
      echo    " * derived from GLOBUS_ERROR_TYPE_${type}   */"
      echo  "extern ${fieldtype}"
      echo  "globus_error_${typelc}_get_${fieldname} (globus_object_t * error)"

      case $1 in 
         declarations)
            echo ";"
         ;;
         definitions)
            echo "{"
            echo "  globus_error_${typelc}_instance_t * instance_data;"
            echo "  instance_data"
            echo "   = globus_l_error_${typelc}_instance_data (error);"
            echo "  if (instance_data != NULL) {"
            echo "    return (instance_data->${fieldname});"
            echo "  }"
            echo "  else return ${failval};"
            echo "}"
         ;;
      esac

         ;;
      esac

      echo ""

      case $1 in 
         docmethods)
            cat <<EOF

<func>
<type> void </type>
<name> globus_error_${typelc}_set_${fieldname} </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> error </fargname> </farg> 
   <farg> <fargtype> ${fieldtype} </fargtype> 
         <fargname> ${fieldname} </fargname> </farg> 
</fargs>
<description>

Associates the ${fieldname} that triggered the error, or does nothing
 if error is a static error, if error is not derived from 
 <ref> GLOBUS_ERROR_TYPE_${type} </ref> , or if error is NULL.

<p>

</description>
</func>

EOF
         ;;
         definitions | declarations)
      echo    "/* set the ${fieldname} instance data of an error"
      echo    " * derived from GLOBUS_ERROR_TYPE_${type}   */"
      echo  "extern void"
      echo  "globus_error_${typelc}_set_${fieldname} ("
      echo  "    globus_object_t * error,"
      echo  "    ${fieldtype} value)"

      case $1 in
         declarations)
            echo ";"
         ;;
         definitions)
            echo "{"
            echo "  globus_error_${typelc}_instance_t * instance_data;"
            echo "  instance_data"
            echo "   = globus_l_error_${typelc}_instance_data (error);"
            echo "  if (instance_data != NULL) {"
            echo "    instance_data->${fieldname} = value;"
            echo "  }"
            echo "}"
         ;;
      esac

         ;;
      esac


      echo ""

   done
   IFS=":{}"
}

driver_loop ()
{
saveIFS="$IFS"
IFS=":{}"
while read type ptype fields stringfunc indication
do
    type="`echo $type | sed -e 's/^ *//g' -e 's/ *$//g'`"
    typelc="`echo $type \
          | sed -e 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/'`"
    ptype="`echo $ptype | sed -e 's/^ *//g' -e 's/ *$//g'`"
    ptypelc="`echo $ptype \
          | sed -e 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/'`"
    fields="`echo $fields | sed -e 's/^ *//g' -e 's/ *$//g'`"

    rename_fields=""
    IFS=","
    for field in $fields
    do
       fieldtype="`echo $field | sed -e 's/^ *//g' -e 's/ *[^ ,][^ ,]*$//g'`"
       fieldname="`echo $field | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
       rename_fields="${rename_fields},${fieldtype} ${typelc}_${fieldname}"
    done
    IFS=":{}"

    fields=`echo "$rename_fields" | sed -e 's/^[, ]*//g'`

    case "X$type" in
      XBASE)
         eval "afields_${type}=\"${fields}\""
      ;;
      X\#* | X)
        :
      ;;
      *)
         eval "pfields=\"\${afields_${ptype}}\""

         if [ "X${fields}" = "X" ]
         then
            eval "afields_${type}=\"\${afields_${ptype}}\""
         elif [ "X${pfields}" = "X" ]
         then
            eval "afields_${type}=\"${fields}\""
         else
            eval "afields_${type}=\"\${afields_${ptype}},${fields}\""
         fi

         case $1 in
            docmethods)

               if [ "X$2" = "Xindex" ]
               then
                 generate_type_method_index
               else
                 echo "<section>"
                 echo "<sectiontitle> Methods for GLOBUS_ERROR_TYPE_${type} </sectiontitle>"
                 echo "" 
                 generate_type_constructors $1
                 generate_type_instance_accessors $1
                 echo "</section>"
               fi
            ;;
            declarations)
               generate_type_def $1
               generate_type_constructors $1
               generate_type_instance_type $1
               generate_type_instance_accessors $1
            ;;
            definitions)
               generate_type_instance_type $1
               generate_type_instance_copy $1
               generate_type_instance_destroy $1
               generate_type_def $1
               generate_type_constructors $1
               generate_type_instance_accessors $1
            ;;
         esac

         echo ""
      ;;
   esac
done
}

if [ "X$1" = "Xdeclarations" ]
then
    cat <<EOF

#ifndef GLOBUS_ERROR_HIERARCHY_H
#define GLOBUS_ERROR_HIERARCHY_H


#include "globus_common.h"

#include "globus_object.h"
#include "globus_error.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif
 
EXTERN_C_BEGIN

/* the following code all generated by running the script
 * ./globus_error_hierarchy.h.sh $1 < globus_error_hierarchy.idl
 */

EOF

   driver_loop $1

   cat <<EOF

EXTERN_C_END

#endif /* GLOBUS_ERROR_HIERARCHY_H */

EOF


elif [ "X$1" = "Xdefinitions" ]
then


    cat <<EOF
#include <assert.h>

#include "globus_common.h"

/* the following code all generated by running the script
 * ./globus_error_hierarchy.h.sh $1 < globus_error_hierarchy.idl
 */

EOF

    driver_loop $1

elif [ "X$1" = "Xdocmethods" ]
then
    rm -f /tmp/globus_error_idl.$$
    cat > /tmp/globus_error_idl.$$

    cat <<EOF

<doctitle> Standard Globus Error Types </doctitle>
<docbody>

<section>

<h2> <fontsize=4> Standard Globus Error Types </fontsize> </h2>

This is a document to specify the proposed Globus Error Type interfaces
 to be introduced with the Globus v1.1
release.

<p>

</section>

<section>
<sectiontitle> Type/Method Index </sectiontitle>
<object> <type> globus_object_type_t * </type> 
        <name> GLOBUS_ERROR_TYPE_BASE </name>
<description>

The error hierarchy is rooted at GLOBUS_ERROR_TYPE_BASE.  All routines
in the Globus Error Interface require objects instantiating a type
derived from GLOBUS_ERROR_TYPE_BASE.

<p>

This type introduces instance data and the following methods 
which are documented in the next section:
<ul>
   <li> <ref> globus_error_construct_base </ref> ()</li>
   <li> <ref> globus_error_initialize_base </ref> ()</li>
   <li> <ref> globus_error_base_get_source </ref> () 
        / <ref> globus_error_base_set_source </ref> ()</li>
   <li> <ref> globus_error_base_get_cause </ref> () 
        / <ref> globus_error_base_set_cause </ref> ()</li>
</ul>

<p>

This type indicates that some error occurred during the operation.

<p>

This type is derived from <ref> GLOBUS_OBJECT_TYPE_PRINTABLE </ref> .

</description>
</object>

EOF
    # generate method index for each IDL type
    driver_loop $1 index < /tmp/globus_error_idl.$$
    cat <<EOF
</section>


<section>
<sectiontitle> Methods for GLOBUS_ERROR_TYPE_BASE </sectiontitle>

<func> 
<type> globus_object_t * </type>
<name> globus_error_construct_base </name> 
<fargs>  
   <farg> <fargtype> globus_module_descriptor_t * </fargtype> 
         <fargname> source_module </fargname> </farg> 
   <farg> <fargtype> globus_object_t * </fargtype>  
         <fargname> causal_error </fargname> </farg> 
</fargs>
<description>

Equivalent to: <br>
<tab> globus_error_initialize_base(<br>
<tab> <tab> <tab> globus_object_construct( <ref> GLOBUS_ERROR_TYPE_BASE </ref> ), <br>
<tab> <tab> <tab> source_module, <br>
<tab> <tab> <tab> causal_error) .

<p>

</description>
</func> 


<func> 
<type> globus_object_t * </type>
<name> globus_error_initialize_base </name> 
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> error </fargname> </farg> 
   <farg> <fargtype> globus_module_descriptor_t * </fargtype> 
         <fargname> source_module </fargname> </farg> 
   <farg> <fargtype> globus_object_t * </fargtype>  
         <fargname> causal_error </fargname> </farg> 
</fargs>
<description>

Initialize the <ref> GLOBUS_ERROR_TYPE_BASE </ref> instance data of error with the given
source_module and causal_error values and return the error, or return 
NULL if either error is NULL, error is static, or error is not derived from <ref> GLOBUS_ERROR_TYPE_BASE </ref> .

<p>


<p>
In general, an 
initializer globus_error_initialize_&lt;type&gt;() should be defined
for every extended error type.

</description>
</func> 

<func>
<type> globus_module_descriptor_t * </type>
<name> globus_error_base_get_source </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> error </fargname> </farg> 
</fargs>
<description>

Returns the module descriptor of the module that generated the error, or
returns NULL if error is a static error, if error is not derived from <ref> GLOBUS_ERROR_TYPE_BASE </ref> , or if error is NULL.

<p>

Static errors are those for which globus_object_is_static(error) returns GLOBUS_TRUE.

</description>
</func>

<func>
<type> void </type>
<name> globus_error_base_set_source </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> error </fargname> </farg> 
   <farg> <fargtype> globus_module_descriptor_t * </fargtype> 
         <fargname> source_module </fargname> </farg> 
</fargs>
<description>

Sets the module descriptor of the module that generated the error, or
does nothing if error is a static error, if error is not derived from <ref> GLOBUS_ERROR_TYPE_BASE </ref> , or if error is NULL.

<p>

Static errors are those for which globus_object_is_static(error) returns GLOBUS_TRUE.

<p>

This routine would normally only be called by the constructor function
for the error since the source of an error should not change.

</description>
</func>

<func>
<type> globus_object_t * </type>
<name> globus_error_base_get_cause </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> error </fargname> </farg> 
</fargs>
<description>

Returns the error that triggered the error, or returns GLOBUS_ERROR_NO_INFO
if either no causal error is known or error is a static error, or returns 
NULL if error is not derived from <ref> GLOBUS_ERROR_TYPE_BASE </ref> , or if error is NULL.


</description>
</func>

<func>
<type> void </type>
<name> globus_error_base_set_cause </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> error </fargname> </farg> 
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> causal_error </fargname> </farg> 
</fargs>
<description>

Associates the error that triggered the error, or does nothing
 if error is a static error, if error is not derived from <ref> GLOBUS_ERROR_TYPE_BASE </ref> , or if error is NULL.

<p>

This routine would normally only be called by the constructor function
for the error since the cause of an error should not change.

</description>
</func>

</section>


EOF

    driver_loop $1 < /tmp/globus_error_idl.$$
    rm -f /tmp/globus_error_idl.$$

    cat <<EOF

<modified> <filemoddate> </modified>
</docbody>

EOF


fi

