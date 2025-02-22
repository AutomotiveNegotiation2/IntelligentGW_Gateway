# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Produce verbose output by default.
VERBOSE = 1

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/root/Project_Relayserver

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/root/Project_Relayserver

# Include any dependencies generated for this target.
include src/app/relayserver_test/CMakeFiles/relay_test_app.dir/depend.make

# Include the progress variables for this target.
include src/app/relayserver_test/CMakeFiles/relay_test_app.dir/progress.make

# Include the compile flags for this target's objects.
include src/app/relayserver_test/CMakeFiles/relay_test_app.dir/flags.make

src/app/relayserver_test/CMakeFiles/relay_test_app.dir/src/relay_test_app.c.o: src/app/relayserver_test/CMakeFiles/relay_test_app.dir/flags.make
src/app/relayserver_test/CMakeFiles/relay_test_app.dir/src/relay_test_app.c.o: src/app/relayserver_test/src/relay_test_app.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/root/Project_Relayserver/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/app/relayserver_test/CMakeFiles/relay_test_app.dir/src/relay_test_app.c.o"
	cd /home/root/Project_Relayserver/src/app/relayserver_test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/relay_test_app.dir/src/relay_test_app.c.o   -c /home/root/Project_Relayserver/src/app/relayserver_test/src/relay_test_app.c

src/app/relayserver_test/CMakeFiles/relay_test_app.dir/src/relay_test_app.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/relay_test_app.dir/src/relay_test_app.c.i"
	cd /home/root/Project_Relayserver/src/app/relayserver_test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/root/Project_Relayserver/src/app/relayserver_test/src/relay_test_app.c > CMakeFiles/relay_test_app.dir/src/relay_test_app.c.i

src/app/relayserver_test/CMakeFiles/relay_test_app.dir/src/relay_test_app.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/relay_test_app.dir/src/relay_test_app.c.s"
	cd /home/root/Project_Relayserver/src/app/relayserver_test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/root/Project_Relayserver/src/app/relayserver_test/src/relay_test_app.c -o CMakeFiles/relay_test_app.dir/src/relay_test_app.c.s

# Object files for target relay_test_app
relay_test_app_OBJECTS = \
"CMakeFiles/relay_test_app.dir/src/relay_test_app.c.o"

# External object files for target relay_test_app
relay_test_app_EXTERNAL_OBJECTS =

src/app/relayserver_test/relay_test_app: src/app/relayserver_test/CMakeFiles/relay_test_app.dir/src/relay_test_app.c.o
src/app/relayserver_test/relay_test_app: src/app/relayserver_test/CMakeFiles/relay_test_app.dir/build.make
src/app/relayserver_test/relay_test_app: src/lib/relayserver/librelayserver.so
src/app/relayserver_test/relay_test_app: src/lib/parson/libparson.so
src/app/relayserver_test/relay_test_app: src/lib/memory_allocation/libmemory_allocation.so
src/app/relayserver_test/relay_test_app: src/app/relayserver_test/CMakeFiles/relay_test_app.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/root/Project_Relayserver/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable relay_test_app"
	cd /home/root/Project_Relayserver/src/app/relayserver_test && /usr/bin/cmake -E remove /home/root/Project_Relayserver/output/bin//relay_test_app
	cd /home/root/Project_Relayserver/src/app/relayserver_test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/relay_test_app.dir/link.txt --verbose=$(VERBOSE)
	cd /home/root/Project_Relayserver/src/app/relayserver_test && /usr/bin/cmake -E copy relay_test_app /home/root/Project_Relayserver/output/bin/

# Rule to build all files generated by this target.
src/app/relayserver_test/CMakeFiles/relay_test_app.dir/build: src/app/relayserver_test/relay_test_app

.PHONY : src/app/relayserver_test/CMakeFiles/relay_test_app.dir/build

src/app/relayserver_test/CMakeFiles/relay_test_app.dir/clean:
	cd /home/root/Project_Relayserver/src/app/relayserver_test && $(CMAKE_COMMAND) -P CMakeFiles/relay_test_app.dir/cmake_clean.cmake
.PHONY : src/app/relayserver_test/CMakeFiles/relay_test_app.dir/clean

src/app/relayserver_test/CMakeFiles/relay_test_app.dir/depend:
	cd /home/root/Project_Relayserver && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/root/Project_Relayserver /home/root/Project_Relayserver/src/app/relayserver_test /home/root/Project_Relayserver /home/root/Project_Relayserver/src/app/relayserver_test /home/root/Project_Relayserver/src/app/relayserver_test/CMakeFiles/relay_test_app.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/app/relayserver_test/CMakeFiles/relay_test_app.dir/depend

