idf_component_register(SRCS "ccid_frame.c" "t1.c" "ccid_host.c" INCLUDE_DIRS "include" REQUIRES usb esp_timer)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
