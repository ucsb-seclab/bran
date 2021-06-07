add_library(CallGraphInfoDumper MODULE src/CallGraphInfoDumper.cpp
        include/CallGraphNodeDumper.h src/CallGraphNodeDumper.cpp)

include_directories(include)

target_compile_features(CallGraphInfoDumper PRIVATE cxx_range_for cxx_auto_type)

set_target_properties(CallGraphInfoDumper PROPERTIES
        COMPILE_FLAGS "-g -ggdb"
        )

if(APPLE)
    set_target_properties(CallGraphInfoDumper PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            )
endif(APPLE)
