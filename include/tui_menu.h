#ifndef TUI_MENU_H
#define TUI_MENU_H

#include "common/constants.h"
#include <string>
#include <vector>

Action show_menu(std::vector<std::string> &output_log);
Action show_numeric_menu();

#endif
