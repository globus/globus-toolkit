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
        echo "             GLOBUS_OBJECT_TYPE_${type}_DEFINITION;"
        echo ""
        echo "#define GLOBUS_OBJECT_TYPE_${type} \\"
        echo "        (&GLOBUS_OBJECT_TYPE_${type}_DEFINITION)"
        echo ""
     ;;
     definitions)
        echo "const globus_object_type_t GLOBUS_OBJECT_TYPE_${type}_DEFINITION"
        echo "= globus_object_type_static_initializer ("
        echo "        (&GLOBUS_OBJECT_TYPE_${ptype}_DEFINITION),"

        if [ ! "X$fields" = "X" ]
        then
           echo "        globus_l_object_${typelc}_copy,"
           echo "        globus_l_object_${typelc}_destroy,"
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
            echo "  globus_object_${typelc}_set_${fieldname} (object, ${fieldname});"
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
         echo    "/* allocate and initialize an object of type"
         echo    " * GLOBUS_OBJECT_TYPE_${type}   */"
         echo    "extern globus_object_t *"
         echo    "globus_object_construct_${typelc} ("

         generate_type_constructor_args declarations

   echo -n ")"
      ;;
      docmethods)
         cat <<EOF
<func>
<type> globus_object_t * </type>
<name> globus_object_construct_${typelc} </name>
<fargs>
EOF
         generate_type_constructor_args docmethods

         eval "afields=\"\${afields_${type}}\""
         if [ "X$afields" = "X" ]
         then
            cat <<EOF
</fargs>
<description>

Equivalent to globus_object_construct( <ref> GLOBUS_OBJECT_TYPE_${type} </ref> ) .

</description>
</func>

EOF
         else
            cat <<EOF
</fargs>
<description>

Equivalent to:<br>
<tab>  globus_object_initialize_${typelc} (<br>
<tab> <tab> <tab> <tab> globus_object_construct( <ref> GLOBUS_OBJECT_TYPE_${type} </ref> ) . . . ) .

</description>
</func>

EOF
         fi
      ;;
   esac
   case $1 in 
      declarations)
        echo ";"
      ;;
      definitions)
        echo ""
        echo "{"
        echo "  globus_object_t * newobject, * object;"
        echo "  newobject = globus_object_construct (GLOBUS_OBJECT_TYPE_${type});"
        echo ""
        echo "  object = globus_object_initialize_${typelc} ("

   eval "ifields=\"\${afields_${type}}\""

   if [ ! "X$ifields" = "X" ]
   then
        echo    "    newobject,"
   else
        echo    "    newobject"
   fi

        generate_type_constructor_args references
        echo ");"
        echo ""
        echo "  if (object==NULL) globus_object_free (newobject);"
        echo ""
        echo "  return object;"
        echo "}"
      ;;
   esac

   echo    ""

   case $1 in
      declarations | definitions)
   echo    "/* initialize and return an object of type"
   echo    " * GLOBUS_OBJECT_TYPE_${type}   */"
   echo    "extern globus_object_t *"
   echo    "globus_object_initialize_${typelc} ("

   eval "ifields=\"\${afields_${type}}\""

   if [ ! "X$ifields" = "X" ]
   then
        echo    "    globus_object_t * object,"
   else
        echo    "    globus_object_t * object"
   fi

   generate_type_constructor_args declarations

   echo -n ")"
      ;;
      docmethods)
         cat <<EOF
<func>
<type> globus_object_t * </type>
<name> globus_object_initialize_${typelc} </name>
<fargs>
    <farg> <fargtype> globus_object_t * </fargtype>
           <fargname> object </fargname> </farg>
EOF
         generate_type_constructor_args docmethods
         
         eval "afields=\"\${afields_${type}}\""
         if [ "X$afields" = "X" ]
         then
            cat <<EOF
</fargs>
<description>

Equivalent to (object).


</description>
</func>

EOF
         else
            cat <<EOF
</fargs>
<description>

Initialize the instance data of object with the given values and return 
the object, or return NULL if either object is NULL,
object is static, or object is not derived from 
<ref> GLOBUS_OBJECT_TYPE_${type} </ref> . 

</description>
</func>

EOF
         fi
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
        echo "  return globus_object_initialize_${ptypelc} ("

   eval "ifields=\"\${afields_${ptype}}\""

   if [ ! "X$ifields" = "X" ]
   then
        echo    "    object,"
   else
        echo    "    object"
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
      echo "typedef struct globus_object_${typelc}_instance_s {"

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

      echo "} globus_object_${typelc}_instance_t;"
      echo ""

      echo "static globus_object_${typelc}_instance_t *"
      echo "globus_l_object_${typelc}_instance_data (globus_object_t *object)"
      echo "{"
      echo "  globus_object_${typelc}_instance_t * instance_data;"
      echo "  globus_object_t * local_object;"
      echo ""
      echo "  local_object "
      echo "  = globus_object_upcast (object, GLOBUS_OBJECT_TYPE_${type});"
      echo ""
      echo "  if (local_object==NULL) return NULL;"
      echo ""
      echo "  instance_data "
      echo "  = ((globus_object_${typelc}_instance_t *)"
      echo "     globus_object_get_local_instance_data (local_object));"
      echo ""
      echo "  if (instance_data!=NULL) return instance_data;"
      echo "  else {"
      echo "    instance_data "
      echo "    = globus_malloc (sizeof(globus_object_${typelc}_instance_t));"
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
         <name> GLOBUS_OBJECT_TYPE_${type} </name>
<description>

This type represents ${represents}.

<p>

This type introduces the following methods:
<ul>
   <li> <ref> globus_object_construct_${typelc} </ref> ()</li>
   <li> <ref> globus_object_initialize_${typelc} </ref> ()</li>
EOF

      IFS=,
      for field in $fields
      do
         fieldname="`echo $field \
                       | sed -e 's/ *$//g' -e 's/.* \([^ ,][^ ,]*\)$/\1/g'`"
         cat <<EOF
   <li> <ref> globus_object_${typelc}_get_${fieldname} </ref> () /
        <ref> globus_object_${typelc}_set_${fieldname} </ref> ()</li>
EOF
     done
      IFS=":{}"

   cat <<EOF
</ul>

<p>

This type is derived from <ref> GLOBUS_OBJECT_TYPE_${ptype} </ref> .

</description>
</object>

EOF
}

generate_type_instance_copy ()
{
   if [ "$1" = "definitions" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "static void globus_l_object_${typelc}_copy (void *srcvp, void **dstvpp)"
      echo "{"
      echo "  globus_object_${typelc}_instance_t *src, *dst;"
      echo "  if (srcvp==NULL || dstvpp==NULL) return;"
      echo "  src = ((globus_object_${typelc}_instance_t *) srcvp);"
      echo "  (*dstvpp) = globus_malloc (sizeof(globus_object_${typelc}_instance_t));"
      echo "  dst = ((globus_object_${typelc}_instance_t *) (*dstvpp));"
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
      echo "static void globus_l_object_${typelc}_copy (void *src, void **dst);"
      echo ""
   fi
}

generate_type_instance_destroy ()
{
   if [ "$1" = "definitions" ] && \
      [ ! "X$fields" = "X" ]
   then
      echo "static void globus_l_object_${typelc}_destroy (void *datavp)"
      echo "{"
      echo "  globus_object_${typelc}_instance_t *data;"
      echo "  if (datavp==NULL) return;"
      echo "  data = ((globus_object_${typelc}_instance_t *) datavp);"

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
      echo "static void globus_l_object_${typelc}_destroy (void *data);"
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
<name> globus_object_${typelc}_get_${fieldname} </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
          <fargname> object </fargname> </farg> 
</fargs>
<description>

Returns the ${fieldname} with which the object is associated, 
or returns ${failval} if no ${fieldname} is known, if object is a static object, 
if object is not derived from <ref> GLOBUS_OBJECT_TYPE_${type} </ref> ,
or if object is NULL.

<p>

</description>
</func>

EOF
         ;;
         definitions | declarations)

      echo    "/* return the ${fieldname} instance data of an object"
      echo    " * derived from GLOBUS_OBJECT_TYPE_${type}   */"
      echo  "extern ${fieldtype}"
      echo  "globus_object_${typelc}_get_${fieldname} (globus_object_t * object)"

      case $1 in 
         declarations)
            echo ";"
         ;;
         definitions)
            echo "{"
            echo "  globus_object_${typelc}_instance_t * instance_data;"
            echo "  instance_data"
            echo "   = globus_l_object_${typelc}_instance_data (object);"
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
<name> globus_object_${typelc}_set_${fieldname} </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> object </fargname> </farg> 
   <farg> <fargtype> ${fieldtype} </fargtype> 
         <fargname> ${fieldname} </fargname> </farg> 
</fargs>
<description>

Associates the ${fieldname} that triggered the object, or does nothing
 if object is a static object, if object is not derived from 
 <ref> GLOBUS_OBJECT_TYPE_${type} </ref> , or if object is NULL.

<p>

</description>
</func>

EOF
         ;;
         definitions | declarations)
      echo    "/* set the ${fieldname} instance data of an object"
      echo    " * derived from GLOBUS_OBJECT_TYPE_${type}   */"
      echo  "extern void"
      echo  "globus_object_${typelc}_set_${fieldname} ("
      echo  "    globus_object_t * object,"
      echo  "    ${fieldtype} value)"

      case $1 in
         declarations)
            echo ";"
         ;;
         definitions)
            echo "{"
            echo "  globus_object_${typelc}_instance_t * instance_data;"
            echo "  instance_data"
            echo "   = globus_l_object_${typelc}_instance_data (object);"
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
while read type ptype fields stringfunc represents
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
      XPRINTABLE)
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
                 echo "<sectiontitle> Methods for GLOBUS_OBJECT_TYPE_${type} </sectiontitle>"
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

#ifndef GLOBUS_OBJECT_HIERARCHY_H
#define GLOBUS_OBJECT_HIERARCHY_H

#include <stdio.h>

#include "globus_common.h"
#include "globus_object.h"

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
 * ./globus_object_hierarchy.h.sh $1 < globus_object_hierarchy.idl
 */

EOF

   driver_loop $1

   cat <<EOF

EXTERN_C_END

#endif /* GLOBUS_OBJECT_HIERARCHY_H */

EOF


elif [ "X$1" = "Xdefinitions" ]
then


    cat <<EOF
#include <assert.h>

#include "globus_common.h"

/* the following code all generated by running the script
 * ./globus_object_hierarchy.h.sh $1 < globus_object_hierarchy.idl
 */

EOF

    driver_loop $1

elif [ "X$1" = "Xdocmethods" ]
then
    rm -f /tmp/globus_object_idl.$$
    cat > /tmp/globus_object_idl.$$

    cat <<EOF

<doctitle> Standard Globus Object Types </doctitle>
<docbody>

<section>

<h2> <fontsize=4> Standard Globus Object Types </fontsize> </h2>

This is a document to specify the proposed Globus Object Type interfaces
 to be introduced with the Globus v1.1
release.

<p>

</section>

<section>
<sectiontitle> Type/Method Index </sectiontitle>

<object> <type> globus_object_type_t * </type> 
        <name> GLOBUS_OBJECT_TYPE_BASE </name>
<description>

The normal object hierarchy is rooted at GLOBUS_OBJECT_TYPE_BASE.
This type has no instance data and therefore no type-specific manipulators.
It is possible for new root types to be defined (the system allows
a forest of types, not just a tree), so this is not necessarily the
parent of all types.

<p>

This type introduces the following methods which are documented in the next section:

<ul>
   <li> <ref> globus_object_construct_base </ref> ()</li>
   <li> <ref> globus_object_initialize_base </ref> ()</li>
</ul>

</description>
</object>

<object> <type> globus_object_type_t * </type> 
        <name> GLOBUS_OBJECT_TYPE_PRINTABLE </name>
<description>

This type provides a mechanism to translate 
an object to a human-readable string.  This mechanism is specialized by
derived types to give type-specific human-readable strings.

<p>

This type introduces the following methods which are documented in the next section:

<ul>
   <li> <ref> globus_object_construct_printable </ref> ()</li>
   <li> <ref> globus_object_initialize_printable </ref> ()</li>
   <li> <ref> globus_object_printable_to_string </ref> ()</li>
   <li> <ref> globus_object_printable_get_string_func </ref> ()</li>
</ul>

<p>

This type is derived from <ref> GLOBUS_OBJECT_TYPE_BASE </ref> .

</description>
</object>

EOF

    driver_loop $1 index < /tmp/globus_object_idl.$$

    cat <<EOF
</section>

<section>
<sectiontitle> Methods for GLOBUS_OBJECT_TYPE_BASE </sectiontitle>

<func> 
<type> globus_object_t * </type>
<name> globus_object_construct_base </name> 
<fargs>  
</fargs>
<description>

Equivalent to globus_object_construct( <ref> GLOBUS_OBJECT_TYPE_BASE </ref> ) .

<p>

</description>
</func> 


<func> 
<type> globus_object_t * </type>
<name> globus_object_initialize_base </name> 
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> object </fargname> </farg> 
</fargs>
<description>

Equivalent to (object) .

<p>

</description>
</func> 

</section>


<section>
<sectiontitle> Methods for GLOBUS_OBJECT_TYPE_PRINTABLE </sectiontitle>

<func> 
<type> globus_object_t * </type>
<name> globus_object_construct_printable </name> 
<fargs>  
</fargs>
<description>

Equivalent to globus_object_construct( <ref> GLOBUS_OBJECT_TYPE_PRINTABLE </ref> ) .

<p>

</description>
</func> 


<func> 
<type> globus_object_t * </type>
<name> globus_object_initialize_printable </name> 
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> object </fargname> </farg> 
</fargs>
<description>

Equivalent to (object) .

<p>

</description>
</func> 

<func>
<type> char * </type>
<name> globus_object_printable_to_string </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> object </fargname> </farg> 
</fargs>
<description>

Returns a freshly allocated, human-readable ASCII string representing
the given object, or NULL if object is not derived from <ref> GLOBUS_OBJECT_TYPE_PRINTABLE </ref> , or if object is NULL.

</description>
</func>


<func>
<type> globus_object_printable_string_func_t </type>
<name> globus_object_printable_get_string_func </name>
<fargs>  
   <farg> <fargtype> globus_object_t * </fargtype> 
         <fargname> object </fargname> </farg> 
</fargs>
<description>

Returns the string function that will be used by globus_object_printable_to_string() to
export the object as a human-readable string, or returns NULL if object is not derived from <ref> GLOBUS_OBJECT_TYPE_PRINTABLE </ref> or if object is NULL.

<p>

The string function is obtained by searching the object's type and parent
types for the closest (most specialized) non-NULL string function, as
provided in the object type definition using globus_object_printable_type_static_initializer().

<p>

This routine is intended for internal use by globus_object_printable_to_string() and 
other specialized uses.

</description>
</func>

</section>

EOF

    driver_loop $1 < /tmp/globus_object_idl.$$
    rm -f /tmp/globus_object_idl.$$

    cat <<EOF

<modified> <filemoddate> </modified>
</docbody>

EOF


fi

