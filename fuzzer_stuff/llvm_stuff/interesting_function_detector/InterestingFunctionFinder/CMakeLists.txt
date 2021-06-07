add_library(InterestingFunctionFinder MODULE src/InterestingFunctionFinder.cpp
        include/FunctionFinderHelper.h src/FunctionFinderHelper.cpp)

include_directories(include)

target_compile_features(InterestingFunctionFinder PRIVATE cxx_range_for cxx_auto_type)

set_target_properties(InterestingFunctionFinder PROPERTIES
        COMPILE_FLAGS "-g -ggdb"
        )

if(APPLE)
    set_target_properties(InterestingFunctionFinder PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            )
endif(APPLE)
