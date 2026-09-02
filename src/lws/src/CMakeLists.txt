include_directories(.)

message( "--------- INSIDE THE LWS ------")

add_subdirectory(db)
add_subdirectory(rpc)
add_subdirectory(util)
add_subdirectory(wire)

find_package(Boost 1.62 COMPONENTS filesystem regex)
find_package(OpenSSL REQUIRED)

set(beldex-lws-common_sources config.cpp error.cpp)
set(beldex-lws-common_headers config.h error.h fwd.h)

add_library(beldex-lws-common ${beldex-lws-common_sources} ${beldex-lws-common_headers})
target_link_libraries(beldex-lws-common beldex-lws-db)

add_executable(beldex-lws-daemon server_main.cpp scanner.cpp rest_server.cpp)

target_link_libraries(beldex-lws-daemon PUBLIC
    beldex-lws-common
    beldex-lws-rpc
    beldex-lws-util
    PRIVATE
    Boost::serialization
    filesystem
    Boost::thread
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    Boost::regex
)
find_package(ZLIB REQUIRED)
target_link_libraries(beldex-lws-daemon PRIVATE nlohmann_json::nlohmann_json Boost::filesystem ZLIB::ZLIB)

# Scheduled hot backups of a live LWS database; see backup_main.cpp.
add_executable(beldex-lws-backup backup_main.cpp)
target_link_libraries(beldex-lws-backup PRIVATE
    beldex-lws-db
    beldex-lws-common
    beldex-lws-wire-json
    Boost::filesystem
    Boost::program_options
    Threads::Threads
)

add_executable(beldex-lws-admin admin_main.cpp)
target_link_libraries(beldex-lws-admin PRIVATE 
beldex-lws-common
beldex-lws-rpc
beldex-lws-wire-json
nlohmann_json::nlohmann_json
)

# Checks that get_outputs/get_spends(id, min_height) seek to exactly the tail of
# the account's records; see ../tests/min_height_seek.cpp.
if (BUILD_TESTS)
  add_executable(lws-min-height-seek-test ${CMAKE_CURRENT_SOURCE_DIR}/../tests/min_height_seek.cpp)
  # Order matters for static libs: beldex-lws-db (storage.cpp) references
  # lws::error_category() in beldex-lws-common and wire::json_writer in
  # beldex-lws-wire-json, so those must follow it on the link line.
  target_link_libraries(lws-min-height-seek-test PRIVATE
      beldex-lws-db
      beldex-lws-common
      beldex-lws-wire-json
      Boost::filesystem
      Threads::Threads
  )
  add_test(NAME lws-min-height-seek COMMAND lws-min-height-seek-test)

  # Reproduces the orphaned-reader -> blocked page reuse -> runaway map failure
  # and proves check_readers() fixes it; see ../tests/stale_reader_reclaim.cpp.
  add_executable(lws-stale-reader-test ${CMAKE_CURRENT_SOURCE_DIR}/../tests/stale_reader_reclaim.cpp)
  # `epee` is needed for its include path (lmdb/util.h pulls in epee/span.h);
  # lmdb_lib links common/lmdb PRIVATE so those dirs are not propagated.
  target_link_libraries(lws-stale-reader-test PRIVATE
      lmdb_lib
      lmdb
      epee
      common
      Boost::filesystem
      Threads::Threads
  )
  add_test(NAME lws-stale-reader COMMAND lws-stale-reader-test)
endif ()

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin )
# install(TARGETS beldex-lws-daemon DESTINATION bin)
# install(TARGETS beldex-lws-admin DESTINATION bin)
