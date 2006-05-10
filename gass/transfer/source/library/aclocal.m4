define(lac_base_path, ../../../..)dnl
define(lac_config_path, lac_base_path/Configuration)dnl
define(lac_include_macros,[builtin(include,lac_config_path/[$1])])dnl
lac_include_macros(lac.m4)
