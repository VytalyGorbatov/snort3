
set(FILE_LIST
    tcp_splicer.cc
    tcp_splicer_module.cc
    tcp_splicer_module.h
)

if (STATIC_INSPECTORS)
    add_library(tcp_splicer OBJECT
        ${FILE_LIST}
    )

else (STATIC_INSPECTORS)
    add_dynamic_module(tcp_splicer inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
