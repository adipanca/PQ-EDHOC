# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/ubuntu/PQ-EDHOC/test_pq_mem/.."
  "/home/ubuntu/PQ-EDHOC/test_pq_mem/.."
  "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc"
  "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc/tmp"
  "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc/src/oscore_edhoc_project-stamp"
  "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc/src"
  "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc/src/oscore_edhoc_project-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc/src/oscore_edhoc_project-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/ubuntu/PQ-EDHOC/build_ops_runtime/type0-classic-responder/uoscore_uedhoc/src/oscore_edhoc_project-stamp${cfgdir}") # cfgdir has leading slash
endif()
