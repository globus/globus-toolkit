aptsourcesdir=${sysconfdir}/apt/sources.list.d
taskseldir=${datadir}/tasksel

if CREATE_BAMBOO_SOURCES_LIST
aptsources_DATA = globus-bamboo.list
endif

if CREATE_VERSIONED_SOURCES_LIST
aptsources_DATA = globus.list
endif

tasksel_DATA=globus-tasks.desc

EXTRA_DIST = globus.list.in globus-bamboo.list.in globus-tasks.desc
