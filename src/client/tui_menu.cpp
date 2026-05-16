#include "../../include/tui_menu.h"
#include "ftxui/component/component.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/dom/elements.hpp"
#include <iostream>
#include <sstream>

Action show_numeric_menu() {
    int intention = 0;
    std::cout << "\n--- MEFS Client Menu ---\n";
    std::cout << "1. Download File\n";
    std::cout << "2. Upload File\n";
    std::cout << "3. List Files\n";
    std::cout << "4. Delete File\n";
    std::cout << "5. Quit\n";
    std::cout << "Select: " << std::flush;
    while (!(std::cin >> intention)) {
        std::cin.clear();
        std::cin.ignore();
        std::cerr << "Invalid input, please try again: ";
    }
    switch (intention) {
    case 1: return Action::READ_FROM_FILESYSTEM;
    case 2: return Action::WRITE_TO_FILESYSTEM;
    case 3: return Action::LIST_FILES;
    case 4: return Action::DELETE_FILE;
    default: return Action::CONFUSION;
    }
}

Action show_menu(std::vector<std::string> &output_log) {
    if (!isatty(STDIN_FILENO)) {
        return show_numeric_menu();
    }

    using namespace ftxui;

    std::vector<std::string> entries = {
        "Download File",
        "Upload File",
        "List Files",
        "Delete File",
        "Quit",
    };
    int selected = 0;

    auto menu = Menu(&entries, &selected);

    auto screen = ScreenInteractive::Fullscreen();

    auto component = Renderer(menu, [&] {
        Elements lines;
        lines.push_back(text("MEFS Client") | bold | center);
        lines.push_back(separator());
        lines.push_back(menu->Render());
        if (!output_log.empty()) {
            lines.push_back(separator());
            lines.push_back(text("Output:") | bold);
            for (auto &line : output_log) {
                if (line.empty()) continue;
                lines.push_back(text(line));
            }
        }
        return vbox(std::move(lines)) | border;
    });

    component |= CatchEvent([&](Event event) {
        if (event == Event::Return || event == Event::Character('q')) {
            screen.ExitLoopClosure()();
            return true;
        }
        return false;
    });

    screen.Loop(component);

    switch (selected) {
    case 0: return Action::READ_FROM_FILESYSTEM;
    case 1: return Action::WRITE_TO_FILESYSTEM;
    case 2: return Action::LIST_FILES;
    case 3: return Action::DELETE_FILE;
    default: return Action::CONFUSION;
    }
}
