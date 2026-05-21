#ifndef TUI_MENU_H
#define TUI_MENU_H

#include "common/constants.h"
#include <string>
#include <vector>

struct MenuResult {
    Action action;
    std::string input;
};

Action show_numeric_menu();
MenuResult show_menu(std::vector<std::string> &output_log,
                     const std::vector<std::string> &file_list = {});

#endif
