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
include CMakeFiles/remove.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/remove.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/remove.dir/flags.make

CMakeFiles/remove.dir/remove.c.o: CMakeFiles/remove.dir/flags.make
CMakeFiles/remove.dir/remove.c.o: remove.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/root/Project_Relayserver/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/remove.dir/remove.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/remove.dir/remove.c.o   -c /home/root/Project_Relayserver/remove.c

CMakeFiles/remove.dir/remove.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/remove.dir/remove.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/root/Project_Relayserver/remove.c > CMakeFiles/remove.dir/remove.c.i

CMakeFiles/remove.dir/remove.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/remove.dir/remove.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/root/Project_Relayserver/remove.c -o CMakeFiles/remove.dir/remove.c.s

# Object files for target remove
remove_OBJECTS = \
"CMakeFiles/remove.dir/remove.c.o"

# External object files for target remove
remove_EXTERNAL_OBJECTS =

remove: CMakeFiles/remove.dir/remove.c.o
remove: CMakeFiles/remove.dir/build.make
remove: CMakeFiles/remove.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/root/Project_Relayserver/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable remove"
	/usr/bin/cmake -E remove *.h /home/root/Project_Relayserver/src/lib/include/
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/remove.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/remove.dir/build: remove

.PHONY : CMakeFiles/remove.dir/build

CMakeFiles/remove.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/remove.dir/cmake_clean.cmake
.PHONY : CMakeFiles/remove.dir/clean

CMakeFiles/remove.dir/depend:
	cd /home/root/Project_Relayserver && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/root/Project_Relayserver /home/root/Project_Relayserver /home/root/Project_Relayserver /home/root/Project_Relayserver /home/root/Project_Relayserver/CMakeFiles/remove.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/remove.dir/depend

