# cmake_minimum_required(VERSION 3.16)
# project(FirewallApp)

# set(CMAKE_PREFIX_PATH "/Users/tt/Qt/6.9.3/macos/lib/cmake/Qt6")

# # Tìm Qt6
# find_package(Qt6 REQUIRED COMPONENTS Core Sql)

# # Bật AUTOMOC để xử lý Q_OBJECT
# set(CMAKE_AUTOMOC ON)

# # Thêm file nguồn
# add_executable(FirewallApp
#     models/FirewallRule.cpp
#     models/FirewallPacket.cpp
#     viewmodels/FirewallViewModel.cpp
#     PacketParser.cpp        
#     main.cpp
# )


# # Include folder
# include_directories(
#     ${CMAKE_SOURCE_DIR}
#     models
#     viewmodels
# )

# # Link Qt vào app
# find_library(NFQ_LIB netfilter_queue)
# target_link_libraries(FirewallApp
#     Qt6::Core
#     Qt6::Sql
#     ${NFQ_LIB}        # ← thêm thư viện NFQUEUE
# )
cmake_minimum_required(VERSION 3.16)
project(FirewallApp)

# Qt6
set(CMAKE_PREFIX_PATH "/Users/tt/Qt/6.9.3/macos/lib/cmake/Qt6")
find_package(Qt6 REQUIRED COMPONENTS Core Sql)

# Bật AUTOMOC để xử lý Q_OBJECT
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Include thư mục
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/models
    ${CMAKE_SOURCE_DIR}/viewmodels
)

# Thêm file nguồn
add_executable(FirewallApp
    models/FirewallRule.cpp
    models/FirewallPacket.cpp
    viewmodels/FirewallViewModel.cpp
    PacketParser.cpp        
    main.cpp
)

# Link Qt
target_link_libraries(FirewallApp
    Qt6::Core
    Qt6::Sql
)

# Tìm libnetfilter_queue (Linux only)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQUEUE REQUIRED libnetfilter_queue)
include_directories(${NFQUEUE_INCLUDE_DIRS})
target_link_libraries(FirewallApp ${NFQUEUE_LIBRARIES})

# Compiler flags (nếu cần)
target_compile_options(FirewallApp PRIVATE -Wall -Wextra -std=c++17)
