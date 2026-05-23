# Find SGX SDK
if(DEFINED SGX_DIR)
  set(SGX_PATH ${SGX_DIR})
elseif(DEFINED ENV{SGX_SDK})
  set(SGX_PATH $ENV{SGX_SDK})
elseif(EXISTS /opt/intel/sgxsdk)
  set(SGX_PATH /opt/intel/sgxsdk)
elseif(EXISTS /home/arseny30/tdx/sgxsdk)
  set(SGX_PATH /home/arseny30/tdx/sgxsdk)
else()
  message(WARNING "SGX SDK not found - skipping sgx-enclave")
  return()
endif()

if(NOT EXISTS ${SGX_PATH}/include/sgx.h)
  message(WARNING "Invalid SGX SDK at ${SGX_PATH}")
  return()
endif()

message(STATUS "Found SGX SDK at ${SGX_PATH}")

set(SGX_LIB ${SGX_PATH}/lib64)
set(SGX_SIGNER ${SGX_PATH}/bin/x64/sgx_sign)
set(SGX_EDGER ${SGX_PATH}/bin/x64/sgx_edger8r)

set(SGX_ENCLAVE_EPOCH "2025-11-01 00:00:00")

# Disable CMake's default link flags that break SGX
set(CMAKE_SHARED_LINKER_FLAGS "")

# Generate EDL files
add_custom_command(
  OUTPUT Enclave_t.c Enclave_t.h
  COMMAND ${SGX_EDGER} --trusted ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl 
          --search-path ${SGX_PATH}/include
  MAIN_DEPENDENCY Enclave.edl
)

add_custom_command(
  OUTPUT Enclave_u.c Enclave_u.h
  COMMAND ${SGX_EDGER} --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl
          --search-path ${SGX_PATH}/include  
  MAIN_DEPENDENCY Enclave.edl
)

# Enclave library  
add_library(enclave SHARED Enclave.cpp Enclave_t.c)
target_compile_options(enclave PRIVATE -m64 -O2 -DNDEBUG -DEDEBUG -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector-strong)
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${SGX_PATH}/include ${SGX_PATH}/include/tlibc ${SGX_PATH}/include/libcxx)
target_link_libraries(enclave "-m64 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIB} \
  -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
  -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds -Wl,--defsym,__ImageBase=0")
set_target_properties(enclave PROPERTIES 
  LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds
  ENABLE_EXPORTS OFF
  LINK_WHAT_YOU_USE OFF)

# Sign enclave
add_custom_command(
  OUTPUT enclave.signed.so
  COMMAND faketime -f ${SGX_ENCLAVE_EPOCH} ${SGX_SIGNER} sign
          -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_private.pem
          -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml
          -enclave $<TARGET_FILE:enclave> -out enclave.signed.so
  DEPENDS enclave Enclave_private.pem Enclave.config.xml
  COMMENT "Signing enclave"
)

add_custom_target(enclave-sign ALL DEPENDS enclave.signed.so)

# Extract MR_ENCLAVE (write AWK script to avoid shell escaping issues)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/mr.awk 
  "/enclave_css.body.enclave_hash.m:/ { seen=1; next }\n"
  "seen { for(i=1;i<=NF;i++) if(\$i~/^0x/) { printf tolower(substr(\$i,3)); if(++n==32) exit } }\n")
add_custom_command(
  TARGET enclave-sign POST_BUILD
  COMMAND ${SGX_SIGNER} dump -enclave enclave.signed.so -dumpfile enclave.dump
  COMMAND awk -f ${CMAKE_CURRENT_BINARY_DIR}/mr.awk enclave.dump > mr_enclave.txt
  COMMAND ${CMAKE_COMMAND} -E rm enclave.dump
  COMMENT "Extracting MR_ENCLAVE"
)

# Seal server
add_executable(seal-server seal-server.cpp Enclave_u.c)
target_compile_options(seal-server PRIVATE -m64 -fPIC -Wno-attributes)
target_include_directories(seal-server PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${SGX_PATH}/include)
target_link_libraries(seal-server cocoon tdutils tdnet tdnet_ported SGX::DCAPQuoteGenerate -L${SGX_LIB} sgx_urts sgx_uae_service sgx_ukey_exchange pthread)
add_dependencies(seal-server enclave-sign)

# Seal client
add_executable(seal-client seal-client.cpp)
target_link_libraries(seal-client cocoon tdutils tdnet tdnet_ported SGX::DCAPQuoteGenerate)
