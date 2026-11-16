set(beldex-lws-util_sources gamma_picker.cpp random_outputs.cpp signup_limit.cpp source_location.cpp transactions.cpp)
set(beldex-lws-util_headers cache_generation.h fwd.h gamma_picker.h http_server.h random_outputs.h signup_limit.h source_location.h transactions.h)

add_library(beldex-lws-util ${beldex-lws-util_sources} ${beldex-lws-util_headers})
target_link_libraries(beldex-lws-util PRIVATE 
    beldex-lws-db
    Boost::serialization
    filesystem
    Boost::thread
    Boost::system
    Threads::Threads
    epee
    net
)