# Set cross compiler environment 
# HOST(x86_64-linux) TARGET(arm-linux) 
project(RelayServer)
cmake_minimum_required(VERSION 3.22)
#SET(CMAKE_C_STANDARD 99) # C 
#SET(CMAKE_CXX_STANDARD 23) # C++ 
SET(CMAKE_VERBOSE_MAKEFILE true) 

INCLUDE_DIRECTORIES(output/include/)
LINK_DIRECTORIES(ouput/lib/)

ADD_SUBDIRECTORY(src/lib/memory_allocation)
ADD_SUBDIRECTORY(src/lib/relayserver)

ADD_SUBDIRECTORY(src/app/relayserver_test)
