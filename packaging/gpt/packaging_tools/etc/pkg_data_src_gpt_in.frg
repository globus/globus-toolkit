<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE gpt_package_metadata SYSTEM "globus_package.dtd">

<gpt_package_metadata Name="XXX_PACKAGE_XXX" Format_Version="0.02">
<Aging_Version Major="XXX_MAJOR_XXX" Minor="XXX_MINOR_XXX" Age="XXX_AGE_XXX"/>
<Description>
</Description>
<Version_Stability Release="experimental"/>
<src_pkg>

<Source_Dependencies Type="compile" >
<Dependency Name="globus_core"><Version><Simple_Version Major="2"></Simple_Version></Version></Dependency>
<Dependency Name="globus_core"><Version><Simple_Version Major="2"></Simple_Version></Version></Dependency>
</Source_Dependencies>


<With_Flavors build="yes" />
<Build_Environment>
<cflags>@GPT_CFLAGS@</cflags>
<external_includes>@GPT_EXTERNAL_INCLUDES@</external_includes>
<external_libs>@GPT_EXTERNAL_LIBS@</external_libs>
<external_ldflags>@GPT_EXTERNAL_LDFLAGS@</external_ldflags>
<pkg_libs>XXX_PKGLIBS_XXX</pkg_libs>
</Build_Environment>

</src_pkg>
</gpt_package_metadata>

