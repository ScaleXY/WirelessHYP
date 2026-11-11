idf_component_register(SRCS "crypto.c" "des.c" "sm.c" "pkcs15.c" "card.c" "low_s.c" INCLUDE_DIRS "include" REQUIRES mbedtls bootloader_support)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
