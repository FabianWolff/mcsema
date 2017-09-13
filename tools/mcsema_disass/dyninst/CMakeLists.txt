if (NOT UNIX)
  message (ERROR "The Dyninst frontend currently does not support this OS")
else ()
  add_compile_options(-frtti -std=gnu++1y)
endif ()

find_package(Dyninst REQUIRED)
include_directories(${DYNINST_INCLUDE_DIR})
include_directories(${MCSEMA_GEN_DIR})

set_source_files_properties(
  ${PROTOBUF_OUTPUT_FILE_LIST}
  PROPERTIES GENERATED TRUE
  )

add_executable(mcsema-dyninst-disass
  main.cc
  ArgParser.cc
  ${MCSEMA_GEN_DIR}/CFG.pb.cc
  CFGPrettyPrinter.cc
  CFGWriter.cc
  ExternalFunc.cc
  ExternalFunctionManager.cc
  SectionManager.cc
  )

add_dependencies(mcsema-dyninst-disass generate-protobuf-files)

target_link_libraries(mcsema-dyninst-disass dyninstAPI symtabAPI parseAPI common instructionAPI protobuf)
set_property(TARGET mcsema-dyninst-disass APPEND PROPERTY CMAKE_CXX_FLAGS -frtti -std=gnu++1y)

install(
  TARGETS mcsema-dyninst-disass
  RUNTIME DESTINATION bin
  )
