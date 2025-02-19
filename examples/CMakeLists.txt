add_library(example INTERFACE)
target_include_directories(example INTERFACE
  ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(example INTERFACE
  secp256k1
  $<$<PLATFORM_ID:Windows>:bcrypt>
)
if(NOT BUILD_SHARED_LIBS AND MSVC)
  target_link_options(example INTERFACE /IGNORE:4217)
endif()

add_executable(ecdsa_example ecdsa.c)
target_link_libraries(ecdsa_example example)
add_test(NAME ecdsa_example COMMAND ecdsa_example)

if(SECP256K1_ENABLE_MODULE_ECDH)
  add_executable(ecdh_example ecdh.c)
  target_link_libraries(ecdh_example example)
  add_test(NAME ecdh_example COMMAND ecdh_example)
endif()

if(SECP256K1_ENABLE_MODULE_SCHNORRSIG)
  add_executable(schnorr_example schnorr.c)
  target_link_libraries(schnorr_example example)
  add_test(NAME schnorr_example COMMAND schnorr_example)
endif()

# FROST_SPECIFIC - START
if(SECP256K1_ENABLE_MODULE_FROST)
  add_executable(frost_example frost.c)
  target_link_libraries(frost_example example)
  add_test(NAME frost_example COMMAND frost_example)
  add_executable(frost_dkg_example frost_dkg.c)
  target_link_libraries(frost_dkg_example example)
  add_test(NAME frost_dkg_example COMMAND frost_dkg_example)
  add_library(frost_dkg_link SHARED frost_dkg_link.c)
  target_include_directories(frost_dkg_link PUBLIC ${PROJECT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/../../frost_dkg_multisig)
  target_link_libraries(frost_dkg_link secp256k1)
endif()
# FROST_SPECIFIC - END
