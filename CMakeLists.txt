cmake_minimum_required(VERSION 3.16)
project(FirewallApp)

set(CMAKE_PREFIX_PATH "/Users/tt/Qt/6.9.3/macos/lib/cmake/Qt6")

# Tìm Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Sql)

# Bật AUTOMOC để xử lý Q_OBJECT
set(CMAKE_AUTOMOC ON)

# Thêm file nguồn
add_executable(FirewallApp
    models/FirewallRule.cpp
    viewmodels/FirewallViewModel.cpp
    models/FirewallPacket.cpp
    viewmodels/FirewallViewModel.cpp
    main.cpp
)

# Include folder
include_directories(models viewmodels)

# Link Qt vào app
target_link_libraries(FirewallApp
    Qt6::Core
    Qt6::Sql
)
